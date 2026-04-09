from __future__ import annotations

import json
import shutil
import subprocess
from hashlib import sha1
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import (
    Evidence,
    NormalizedEntity,
    Observation,
    RunData,
    Technology,
    WebApplication,
    new_id,
)
from attackcastle.normalization.correlator import collect_web_targets
from attackcastle.proxy import build_subprocess_env, chromium_proxy_args
from attackcastle.scan_policy import build_scan_policy


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


class WebProbeAdapter:
    name = "httpx"
    capability = "web_probe"
    noise_score = 4
    cost_score = 4

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        targets = collect_web_targets(run_data)[:50]
        return [
            f"httpx -silent -l targets.txt -json -tech-detect -title -status-code -follow-redirects  # {item['url']}"
            for item in targets
        ]

    def _capture_screenshot(
        self,
        *,
        context: AdapterContext,
        url: str,
        proxy_url: str | None,
        timeout_seconds: int,
    ) -> str | None:
        browser_binary = shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chrome")
        if not browser_binary:
            return None
        screenshot_path = context.run_store.artifact_path(self.name, f"screenshot_{_safe_name(url)}.png")
        command = [
            browser_binary,
            "--headless=new",
            "--disable-gpu",
            "--ignore-certificate-errors",
            *chromium_proxy_args(proxy_url),
            f"--screenshot={screenshot_path}",
            url,
        ]
        completed = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=build_subprocess_env(proxy_url),
            check=False,
        )
        if completed.returncode != 0 or not screenshot_path.exists():
            return None
        return str(screenshot_path)

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        targets = collect_web_targets(run_data)
        if not targets:
            return result

        policy = build_scan_policy(context.profile_name, context.config)
        timeout_seconds = int(context.config.get("scan", {}).get("http_timeout_seconds", 20))
        screenshot_timeout = int(context.config.get("web_probe", {}).get("screenshot_timeout_seconds", 20))
        capture_screenshots = bool(context.config.get("web_probe", {}).get("capture_screenshots", False))
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip() or None

        input_path = context.run_store.artifact_path(self.name, "httpx_targets.txt")
        input_path.write_text("\n".join(str(item["url"]) for item in targets), encoding="utf-8")
        command_result = run_command_spec(
            context,
            CommandSpec(
                tool_name=self.name,
                capability=self.capability,
                task_type="ProbeWebServices",
                command=[
                    "httpx",
                    "-silent",
                    "-l",
                    str(input_path),
                    "-json",
                    "-tech-detect",
                    "-title",
                    "-status-code",
                    "-follow-redirects",
                ],
                timeout_seconds=timeout_seconds,
                artifact_prefix="httpx_probe",
                extra_artifacts=[input_path],
            ),
            proxy_url=proxy_url,
        )
        result.tool_executions.append(command_result.execution)
        result.evidence_artifacts.extend(command_result.evidence_artifacts)
        result.task_results.append(command_result.task_result)
        if command_result.task_result.status == "skipped":
            result.warnings.extend(command_result.task_result.warnings)
            return result

        target_lookup = {str(item["url"]): item for item in targets}
        parsed_entities: list[dict[str, Any]] = []
        created = 0

        for line in command_result.stdout_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            url = str(payload.get("url") or payload.get("input") or "").strip()
            if not url:
                continue
            target = target_lookup.get(url, {})
            asset_id = str(target.get("asset_id") or "")
            service_id = str(target.get("service_id") or "") or None
            title = str(payload.get("title") or "").strip() or None
            status_code = int(payload["status_code"]) if payload.get("status_code") is not None else None
            final_url = str(payload.get("final_url") or url)
            tech_stack = [str(item) for item in payload.get("tech", []) if str(item).strip()]
            resolved_ip = str(payload.get("host") or payload.get("ip") or "").strip() or None
            parsed = urlparse(final_url)
            web_app = WebApplication(
                webapp_id=new_id("web"),
                asset_id=asset_id,
                service_id=service_id,
                url=final_url,
                status_code=status_code,
                title=title,
                source_tool=self.name,
                source_execution_id=command_result.execution_id,
                parser_version="httpx_v1",
            )
            result.web_apps.append(web_app)
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="web_probe",
                snippet=f"{final_url} status={status_code} title={title or ''}".strip(),
                artifact_path=str(command_result.stdout_path),
                selector={"kind": "jsonl", "url": final_url},
                source_execution_id=command_result.execution_id,
                parser_version="httpx_v1",
                confidence=0.92,
            )
            result.evidence.append(evidence)
            result.normalized_entities.append(
                NormalizedEntity(
                    entity_id=new_id("entity"),
                    entity_type="WebService",
                    attributes={
                        "scheme": parsed.scheme,
                        "host": parsed.hostname or "",
                        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                        "url": final_url,
                        "title": title,
                        "status_code": status_code,
                        "tech_stack": tech_stack,
                        "resolved_ip": resolved_ip,
                        "profile": policy.profile,
                    },
                    evidence_ids=[evidence.evidence_id],
                    source_tool=self.name,
                    source_task_id=command_result.task_result.task_id,
                    source_execution_id=command_result.execution_id,
                    parser_version="httpx_v1",
                )
            )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.detected",
                    value=True,
                    entity_type="web_app",
                    entity_id=web_app.webapp_id,
                    source_tool=self.name,
                    confidence=0.95,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=command_result.execution_id,
                    parser_version="httpx_v1",
                )
            )
            if tech_stack:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="tech.version_inventory",
                        value=[{"name": item, "confidence": 0.8} for item in tech_stack],
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.85,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=command_result.execution_id,
                        parser_version="httpx_v1",
                    )
                )
            for tech in tech_stack:
                tech_entry = Technology(
                    tech_id=new_id("tech"),
                    asset_id=asset_id,
                    webapp_id=web_app.webapp_id,
                    name=tech,
                    confidence=0.8,
                    source_tool=self.name,
                    source_execution_id=command_result.execution_id,
                    parser_version="httpx_v1",
                )
                result.technologies.append(tech_entry)
                if tech.lower() == "wordpress":
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="tech.wordpress.detected",
                            value=True,
                            entity_type="web_app",
                            entity_id=web_app.webapp_id,
                            source_tool=self.name,
                            confidence=0.95,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=command_result.execution_id,
                            parser_version="httpx_v1",
                        )
                    )
            screenshot_path = None
            if capture_screenshots:
                screenshot_path = self._capture_screenshot(
                    context=context,
                    url=final_url,
                    proxy_url=proxy_url,
                    timeout_seconds=screenshot_timeout,
                )
            if screenshot_path:
                result.evidence_artifacts.append(
                    command_result.evidence_artifacts[0].__class__(
                        artifact_id=new_id("artifact"),
                        kind="screenshot",
                        path=screenshot_path,
                        source_tool=self.name,
                        caption=f"Screenshot for {final_url}",
                        source_task_id=command_result.task_result.task_id,
                        source_execution_id=command_result.execution_id,
                    )
                )
            parsed_entities.append({"type": "WebService", "url": final_url, "status_code": status_code})
            created += 1

        command_result.task_result.parsed_entities = parsed_entities
        command_result.task_result.metrics = {
            "lines_parsed": len([line for line in command_result.stdout_text.splitlines() if line.strip()]),
            "entities_created": created,
            "entities_updated": 0,
        }
        result.facts["web.probed_targets"] = created
        result.facts["web_probe.scanned_urls"] = sorted(str(item["url"]) for item in targets)
        context.audit.write(
            "adapter.completed",
            {"adapter": self.name, "probed_targets": created, "profile": policy.profile},
        )
        return result
