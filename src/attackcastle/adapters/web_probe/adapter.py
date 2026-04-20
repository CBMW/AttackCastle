from __future__ import annotations

import json
import shutil
import subprocess
import ssl
import urllib.error
import urllib.request
from hashlib import sha1
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

from attackcastle.adapters.base import build_tool_execution, normalize_command_termination
from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.adapters.targeting import filter_url_targets_for_task_inputs, normalize_url_key
from attackcastle.adapters.web_probe.parser import detect_technologies, extract_title
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import (
    Asset,
    Evidence,
    EvidenceArtifact,
    NormalizedEntity,
    Observation,
    RunData,
    Service,
    TaskArtifactRef,
    TaskResult,
    Technology,
    WebApplication,
    new_id,
    now_utc,
)
from attackcastle.normalization.correlator import collect_web_targets
from attackcastle.proxy import build_subprocess_env, chromium_proxy_args, open_url
from attackcastle.scan_policy import build_scan_policy
from attackcastle.scope.expansion import is_ip_literal


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _normalize_url_key(value: str | None) -> str:
    return normalize_url_key(value)


def _hostname_lookup(run_data: RunData) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for asset in run_data.assets:
        for candidate in (asset.name, *list(getattr(asset, "aliases", []))):
            host = str(candidate or "").strip().lower().rstrip(".")
            if host and host not in lookup:
                lookup[host] = asset.asset_id
    return lookup


def _service_name_for_url(scheme: str, port: int) -> str:
    return "https" if scheme == "https" or port in {443, 8443} else "http"


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

    def _run_builtin_probe(
        self,
        context: AdapterContext,
        targets: list[dict[str, str | int]],
        *,
        timeout_seconds: int,
        proxy_url: str | None,
        artifact_suffix: str,
    ):
        started_at = now_utc()
        execution_id = new_id("exec")
        task_id = new_id("task")
        stdout_path = context.run_store.artifact_path(self.name, f"builtin_probe_{artifact_suffix}_stdout.jsonl")
        stderr_path = context.run_store.artifact_path(self.name, f"builtin_probe_{artifact_suffix}_stderr.txt")
        transcript_path = context.run_store.artifact_path(self.name, f"builtin_probe_{artifact_suffix}_transcript.txt")
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        def _headers_to_dict(headers) -> dict[str, str]:  # noqa: ANN001
            try:
                return {str(key).lower(): str(value) for key, value in headers.items()}
            except Exception:
                return {}

        def _decode_body(raw: bytes, headers: dict[str, str]) -> str:
            content_type = headers.get("content-type", "")
            charset = "utf-8"
            if "charset=" in content_type:
                charset = content_type.rsplit("charset=", 1)[-1].split(";", 1)[0].strip() or "utf-8"
            return raw.decode(charset, errors="replace")

        for target in targets:
            url = str(target.get("url") or "").strip()
            if not url:
                continue
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "AttackCastle/0.1 web-probe"},
                method="GET",
            )
            try:
                with open_url(
                    request,
                    timeout=timeout_seconds,
                    proxy_url=proxy_url,
                    https_context=ssl_context,
                ) as response:
                    raw_body = response.read(256 * 1024)
                    headers = _headers_to_dict(response.headers)
                    body = _decode_body(raw_body, headers)
                    final_url = str(response.geturl() or url)
                    status_code = int(response.getcode() or 0) or None
            except urllib.error.HTTPError as exc:
                raw_body = exc.read(256 * 1024)
                headers = _headers_to_dict(exc.headers)
                body = _decode_body(raw_body, headers)
                final_url = str(exc.geturl() or url)
                status_code = int(exc.code)
            except Exception as exc:  # noqa: BLE001
                stderr_lines.append(f"{url}: {exc}")
                continue

            parsed = urlparse(final_url or url)
            tech = [name for name, _version, _confidence in detect_technologies(headers, body)]
            payload = {
                "url": url,
                "input": url,
                "final_url": final_url or url,
                "title": extract_title(body),
                "status_code": status_code,
                "tech": tech,
                "host": parsed.hostname or "",
            }
            stdout_lines.append(json.dumps(payload, sort_keys=True))

        stdout_text = "\n".join(stdout_lines)
        stderr_text = "\n".join(stderr_lines)
        stdout_path.write_text(stdout_text + ("\n" if stdout_text else ""), encoding="utf-8")
        stderr_path.write_text(stderr_text + ("\n" if stderr_text else ""), encoding="utf-8")
        transcript_path.write_text("\n".join([stdout_text, stderr_text]).strip(), encoding="utf-8")
        ended_at = now_utc()
        termination_reason, termination_detail, timed_out = normalize_command_termination(0)
        execution = build_tool_execution(
            tool_name=self.name,
            command=f"AttackCastle builtin web probe ({len(targets)} target(s))",
            started_at=started_at,
            ended_at=ended_at,
            status="completed",
            execution_id=execution_id,
            capability=self.capability,
            exit_code=0,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            transcript_path=str(transcript_path),
            raw_artifact_paths=[],
            termination_reason=termination_reason,
            termination_detail=termination_detail,
            timed_out=timed_out,
        )
        task_result = TaskResult(
            task_id=task_id,
            task_type="CheckWebsites",
            status="completed",
            command=execution.command,
            exit_code=0,
            started_at=started_at,
            finished_at=ended_at,
            transcript_path=str(transcript_path),
            raw_artifacts=[
                TaskArtifactRef(artifact_type="stdout", path=str(stdout_path)),
                TaskArtifactRef(artifact_type="stderr", path=str(stderr_path)),
            ],
            parsed_entities=[],
            metrics={"fallback_probe": True, "confirmed_targets": len(stdout_lines), "errors": len(stderr_lines)},
            warnings=[
                "httpx is unavailable; used AttackCastle builtin HTTP(S) probe fallback."
            ],
            termination_reason=termination_reason,
            termination_detail=termination_detail,
            timed_out=timed_out,
            raw_command=execution.raw_command or execution.command,
        )
        evidence_artifacts = [
            EvidenceArtifact(
                artifact_id=new_id("artifact"),
                kind="stdout",
                path=str(stdout_path),
                source_tool=self.name,
                caption="builtin web probe stdout",
                source_task_id=task_id,
                source_execution_id=execution_id,
            ),
            EvidenceArtifact(
                artifact_id=new_id("artifact"),
                kind="stderr",
                path=str(stderr_path),
                source_tool=self.name,
                caption="builtin web probe stderr",
                source_task_id=task_id,
                source_execution_id=execution_id,
            ),
        ]
        return SimpleNamespace(
            execution=execution,
            evidence_artifacts=evidence_artifacts,
            task_result=task_result,
            stdout_text=stdout_text,
            stdout_path=stdout_path,
            execution_id=execution_id,
        )

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        if not bool(context.config.get("web_probe", {}).get("enabled", True)):
            started_at = now_utc()
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="httpx (disabled)",
                    started_at=started_at,
                    ended_at=now_utc(),
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            result.facts["web_probe.available"] = False
            return result
        existing_scanned = {str(item).strip() for item in run_data.facts.get("web_probe.scanned_urls", [])}
        existing_scanned_keys = {_normalize_url_key(item) or item for item in existing_scanned if item}
        targets = [
            target
            for target in collect_web_targets(run_data)
            if str(target["url"]).strip() and _normalize_url_key(str(target["url"])) not in existing_scanned_keys
        ]
        targets = filter_url_targets_for_task_inputs(context, targets)
        if not targets:
            return result

        policy = build_scan_policy(context.profile_name, context.config)
        timeout_seconds = int(context.config.get("scan", {}).get("http_timeout_seconds", 20))
        screenshot_timeout = int(context.config.get("web_probe", {}).get("screenshot_timeout_seconds", 20))
        capture_screenshots = bool(context.config.get("web_probe", {}).get("capture_screenshots", False))
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip() or None

        artifact_suffix = _safe_name(context.task_instance_key or "\n".join(str(item["url"]) for item in targets))
        input_path = context.run_store.artifact_path(self.name, f"httpx_targets_{artifact_suffix}.txt")
        input_path.write_text("\n".join(str(item["url"]) for item in targets), encoding="utf-8")
        command_result = run_command_spec(
            context,
            CommandSpec(
                tool_name=self.name,
                capability=self.capability,
                task_type="CheckWebsites",
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
                artifact_prefix=f"httpx_probe_{artifact_suffix}",
                extra_artifacts=[input_path],
            ),
            proxy_url=proxy_url,
        )
        result.tool_executions.append(command_result.execution)
        result.evidence_artifacts.extend(command_result.evidence_artifacts)
        result.task_results.append(command_result.task_result)
        if command_result.task_result.status == "skipped":
            result.warnings.extend(command_result.task_result.warnings)
            fallback_result = self._run_builtin_probe(
                context,
                targets,
                timeout_seconds=timeout_seconds,
                proxy_url=proxy_url,
                artifact_suffix=artifact_suffix,
            )
            result.tool_executions.append(fallback_result.execution)
            result.evidence_artifacts.extend(fallback_result.evidence_artifacts)
            result.task_results.append(fallback_result.task_result)
            result.warnings.extend(fallback_result.task_result.warnings)
            command_result = fallback_result

        target_lookup: dict[str, dict[str, str | int]] = {}
        for item in targets:
            raw_url = str(item.get("url") or "")
            target_lookup[raw_url] = item
            normalized = _normalize_url_key(raw_url)
            if normalized:
                target_lookup[normalized] = item
        existing_asset_by_host = _hostname_lookup(run_data)
        existing_service_by_asset_port = {
            (str(service.asset_id), int(service.port)): service.service_id
            for service in run_data.services
            if str(service.asset_id).strip()
        }
        created_asset_by_host: dict[str, str] = {}
        created_service_by_asset_port: dict[tuple[str, int], str] = {}
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
            input_url = str(payload.get("input") or "").strip()
            if not url:
                continue
            final_url = str(payload.get("final_url") or url)
            target = (
                target_lookup.get(url)
                or target_lookup.get(_normalize_url_key(url))
                or target_lookup.get(input_url)
                or target_lookup.get(_normalize_url_key(input_url))
                or target_lookup.get(final_url)
                or target_lookup.get(_normalize_url_key(final_url))
                or {}
            )
            asset_id = str(target.get("asset_id") or "")
            service_id = str(target.get("service_id") or "") or None
            title = str(payload.get("title") or "").strip() or None
            status_code = int(payload["status_code"]) if payload.get("status_code") is not None else None
            tech_stack = [str(item) for item in payload.get("tech", []) if str(item).strip()]
            resolved_ip = str(payload.get("host") or payload.get("ip") or "").strip() or None
            parsed = urlparse(final_url)
            if not parsed.hostname:
                parsed = urlparse(url)
            scheme = parsed.scheme.lower() or urlparse(str(target.get("url") or "")).scheme.lower() or "https"
            host = (parsed.hostname or urlparse(str(target.get("url") or "")).hostname or "").lower().rstrip(".")
            port = parsed.port or (443 if scheme == "https" else 80)
            target_host = (urlparse(str(target.get("url") or "")).hostname or "").lower().rstrip(".")
            if asset_id and host and target_host and host != target_host:
                asset_id = ""
            if not asset_id and host:
                asset_id = existing_asset_by_host.get(host, "") or created_asset_by_host.get(host, "")
            if not asset_id and host:
                asset = Asset(
                    asset_id=new_id("asset"),
                    kind="host" if is_ip_literal(host) else "domain",
                    name=host,
                    ip=host if is_ip_literal(host) else None,
                    source_tool=self.name,
                    source_execution_id=command_result.execution_id,
                    parser_version="httpx_v1",
                )
                result.assets.append(asset)
                asset_id = asset.asset_id
                created_asset_by_host[host] = asset.asset_id
            if not service_id and asset_id:
                service_id = existing_service_by_asset_port.get((asset_id, port)) or created_service_by_asset_port.get(
                    (asset_id, port)
                )
            if not service_id and asset_id:
                service = Service(
                    service_id=new_id("svc"),
                    asset_id=asset_id,
                    port=port,
                    protocol="tcp",
                    state="open",
                    name=_service_name_for_url(scheme, port),
                    source_tool=self.name,
                    source_execution_id=command_result.execution_id,
                    parser_version="httpx_v1",
                )
                result.services.append(service)
                service_id = service.service_id
                created_service_by_asset_port[(asset_id, port)] = service.service_id
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
                        "scheme": scheme,
                        "host": host,
                        "port": port,
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
                    EvidenceArtifact(
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
        attempted_urls = {str(item["url"]) for item in targets}
        completed_urls = attempted_urls if command_result.task_result.status == "completed" else set()
        completed_set = existing_scanned.union(completed_urls)
        result.facts["web.probed_targets"] = created
        result.facts["web_probe.attempted_urls"] = sorted(attempted_urls)
        result.facts["web_probe.completed_urls"] = sorted(completed_set)
        result.facts["web_probe.failed_urls"] = sorted(attempted_urls.difference(completed_urls))
        result.facts["web_probe.scanned_urls"] = sorted(completed_set)
        context.audit.write(
            "adapter.completed",
            {"adapter": self.name, "probed_targets": created, "profile": policy.profile},
        )
        return result
