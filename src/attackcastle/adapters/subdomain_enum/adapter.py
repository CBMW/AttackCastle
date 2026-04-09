from __future__ import annotations

import re
from typing import Any

from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Asset, Evidence, NormalizedEntity, Observation, RunData, new_id
from attackcastle.scan_policy import build_scan_policy
from attackcastle.scope.domains import canonical_hostname, registrable_domain
from attackcastle.scope.expansion import is_ip_literal

HOSTNAME_RE = re.compile(r"^(?:\*\.)?[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$", re.IGNORECASE)


class SubdomainEnumAdapter:
    name = "subfinder"
    capability = "subdomain_enumeration"
    noise_score = 2
    cost_score = 3

    def _build_enumeration_plan(self, run_data: RunData) -> list[dict[str, Any]]:
        roots: dict[str, dict[str, Any]] = {}
        for target in run_data.scope:
            host = canonical_hostname(target.host)
            root: str | None = None
            if target.target_type in {TargetType.DOMAIN, TargetType.WILDCARD_DOMAIN} and host:
                root = registrable_domain(host) or host
            elif target.target_type in {TargetType.URL, TargetType.HOST_PORT} and host and not is_ip_literal(host):
                root = registrable_domain(host) or host
            if not root:
                continue
            entry = roots.setdefault(
                root,
                {
                    "root_domain": root,
                    "source_targets": [],
                    "source_target_ids": [],
                    "source_target_types": [],
                },
            )
            if target.value not in entry["source_targets"]:
                entry["source_targets"].append(target.value)
            if target.target_id not in entry["source_target_ids"]:
                entry["source_target_ids"].append(target.target_id)
            target_type = target.target_type.value
            if target_type not in entry["source_target_types"]:
                entry["source_target_types"].append(target_type)
        return [roots[root] for root in sorted(roots)]

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        policy = build_scan_policy(context.profile_name, context.config)
        previews: list[str] = []
        for item in self._build_enumeration_plan(run_data)[:20]:
            root = str(item["root_domain"])
            previews.append(
                f"subfinder -silent -all -d {root} -rl {policy.subfinder_rate_limit} -t {policy.global_concurrency}"
            )
        return previews

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        config = context.config.get("subdomain_enum", {})
        policy = build_scan_policy(context.profile_name, context.config)
        timeout_seconds = int(config.get("timeout_seconds", 90))
        max_candidates = int(config.get("max_candidates", 500))
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip() or None

        plan = self._build_enumeration_plan(run_data)
        discovered: set[str] = set()
        source_counts: dict[str, int] = {}
        discovered_by_root: dict[str, list[str]] = {}
        failed_roots: list[dict[str, Any]] = []
        successful_roots = 0

        for entry in plan:
            root = str(entry["root_domain"])
            command_result = run_command_spec(
                context,
                CommandSpec(
                    tool_name=self.name,
                    capability=self.capability,
                    task_type="EnumerateSubdomains",
                    command=[
                        "subfinder",
                        "-silent",
                        "-all",
                        "-d",
                        root,
                        "-rl",
                        str(policy.subfinder_rate_limit),
                        "-t",
                        str(policy.global_concurrency),
                    ],
                    timeout_seconds=timeout_seconds,
                    artifact_prefix=f"subfinder_{root.replace('*', '_').replace('.', '_')}",
                ),
                proxy_url=proxy_url,
            )
            result.tool_executions.append(command_result.execution)
            result.evidence_artifacts.extend(command_result.evidence_artifacts)
            result.task_results.append(command_result.task_result)
            if command_result.task_result.status == "skipped":
                result.warnings.extend(command_result.task_result.warnings)
                break
            if command_result.task_result.status != "completed":
                source_counts[root] = 0
                failed_roots.append(
                    {
                        "root_domain": root,
                        "source_targets": list(entry["source_targets"]),
                        "source_target_ids": list(entry["source_target_ids"]),
                        "source_target_types": list(entry["source_target_types"]),
                        "termination_reason": command_result.task_result.termination_reason,
                        "termination_detail": command_result.task_result.termination_detail,
                    }
                )
                continue

            root_hits: list[str] = []
            for line in command_result.stdout_text.splitlines():
                candidate = line.strip().lower().rstrip(".")
                if not candidate or not HOSTNAME_RE.match(candidate):
                    continue
                if not candidate.endswith(f".{root}") and candidate != root:
                    continue
                if candidate in discovered:
                    continue
                discovered.add(candidate)
                root_hits.append(candidate)
                asset = Asset(
                    asset_id=new_id("asset"),
                    kind="domain",
                    name=candidate,
                    source_tool=self.name,
                    source_execution_id=command_result.execution_id,
                    parser_version="subfinder_v1",
                )
                result.assets.append(asset)
                evidence = Evidence(
                    evidence_id=new_id("evidence"),
                    source_tool=self.name,
                    kind="subdomain_enumeration",
                    snippet=candidate,
                    artifact_path=str(command_result.stdout_path),
                    selector={"kind": "line", "match": candidate},
                    source_execution_id=command_result.execution_id,
                    parser_version="subfinder_v1",
                    confidence=0.9,
                )
                result.evidence.append(evidence)
                result.normalized_entities.append(
                    NormalizedEntity(
                        entity_id=new_id("entity"),
                        entity_type="Hostname",
                        attributes={
                            "fqdn": candidate,
                            "root_domain": root,
                            "source": self.name,
                            "profile": policy.profile,
                        },
                        evidence_ids=[evidence.evidence_id],
                        source_tool=self.name,
                        source_task_id=command_result.task_result.task_id,
                        source_execution_id=command_result.execution_id,
                        parser_version="subfinder_v1",
                    )
                )
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="dns.subdomain.discovered",
                        value=True,
                        entity_type="asset",
                        entity_id=asset.asset_id,
                        source_tool=self.name,
                        confidence=0.9,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=command_result.execution_id,
                        parser_version="subfinder_v1",
                    )
                )

            command_result.task_result.parsed_entities = [
                {"type": "Hostname", "value": host} for host in root_hits
            ]
            command_result.task_result.metrics = {
                "lines_parsed": len([line for line in command_result.stdout_text.splitlines() if line.strip()]),
                "entities_created": len(root_hits),
                "entities_updated": 0,
            }
            source_counts[root] = len(root_hits)
            discovered_by_root[root] = root_hits
            successful_roots += 1

        if failed_roots:
            failure_summary = ", ".join(
                f"{item['root_domain']} ({item.get('termination_reason') or 'failed'})" for item in failed_roots[:5]
            )
            if successful_roots == 0:
                result.errors.append(
                    f"subdomain enumeration failed for {len(failed_roots)} root domain(s): {failure_summary}"
                )
            else:
                result.warnings.append(
                    f"subdomain enumeration partially failed for {len(failed_roots)} root domain(s): {failure_summary}"
                )

        result.facts["subdomain_enum.domain_count"] = len(plan)
        result.facts["subdomain_enum.discovered_count"] = len(discovered)
        result.facts["subdomain_enum.discovered_hosts"] = sorted(discovered)[:max_candidates]
        result.facts["subdomain_enum.source_counts"] = source_counts
        result.facts["subdomain_enum.execution_plan"] = plan
        result.facts["subdomain_enum.discovered_by_root"] = discovered_by_root
        result.facts["subdomain_enum.failed_roots"] = failed_roots
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "root_domains": len(plan),
                "discovered": len(discovered),
            },
        )
        return result
