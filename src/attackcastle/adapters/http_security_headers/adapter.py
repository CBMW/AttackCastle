from __future__ import annotations

import json
import os
import shutil
from hashlib import sha1
from typing import Any

from attackcastle.adapters.base import build_tool_execution
from attackcastle.adapters.command_runner import CommandSpec, run_command_spec
from attackcastle.adapters.http_security_headers.parser import (
    ParsedHeaderResponse,
    build_header_analysis,
    normalize_header_map,
    parse_raw_response_headers,
    summarize_analysis,
)
from attackcastle.adapters.targeting import filter_url_targets_for_task_inputs, normalize_url_key
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, EvidenceArtifact, Observation, RunData, new_id, now_utc
from attackcastle.normalization.correlator import collect_confirmed_web_targets

TASK_TYPE = "CheckHttpSecurityHeaders"
PARSER_VERSION = "http_security_headers_v1"


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def build_linux_head_command(target: str) -> list[str]:
    return ["curl", "-skI", "--max-redirs", "0", str(target)]


def build_linux_fallback_command(target: str) -> list[str]:
    return ["curl", "-skD", "-", "-o", "/dev/null", "--max-redirs", "0", str(target)]


def build_windows_head_command(target: str, *, shell_path: str = "powershell") -> list[str]:
    return _build_windows_command(target, method="Head", shell_path=shell_path)


def build_windows_fallback_command(target: str, *, shell_path: str = "powershell") -> list[str]:
    return _build_windows_command(target, method="Get", shell_path=shell_path)


def _build_windows_command(target: str, *, method: str, shell_path: str) -> list[str]:
    escaped_target = str(target).replace("'", "''")
    escaped_method = str(method).replace("'", "''")
    script = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}
function Get-HeaderRows($HeaderBag) {{
  $rows = @()
  if ($null -eq $HeaderBag) {{
    return $rows
  }}
  if ($HeaderBag.PSObject.Properties['AllKeys']) {{
    foreach ($name in ($HeaderBag.AllKeys | Sort-Object)) {{
      $value = [string]$HeaderBag[$name]
      $rows += [PSCustomObject]@{{ name = $name; value = $value }}
    }}
    return $rows
  }}
  foreach ($entry in ($HeaderBag.GetEnumerator() | Sort-Object Name)) {{
    $rows += [PSCustomObject]@{{ name = [string]$entry.Name; value = [string]$entry.Value }}
  }}
  return $rows
}}
function Emit-Result($Response, $MethodName) {{
  $statusCode = $null
  $statusDescription = ''
  $protocolVersion = 'HTTP/1.1'
  $headers = @()
  if ($null -ne $Response) {{
    try {{ $statusCode = [int]$Response.StatusCode }} catch {{}}
    try {{ $statusDescription = [string]$Response.StatusDescription }} catch {{}}
    try {{
      if ($Response.ProtocolVersion) {{
        $protocolVersion = 'HTTP/' + $Response.ProtocolVersion.ToString()
      }}
    }} catch {{}}
    try {{ $headers = Get-HeaderRows $Response.Headers }} catch {{}}
  }}
  $rawLines = @()
  if ($null -ne $statusCode) {{
    $rawLines += ('{{0}} {{1}} {{2}}' -f $protocolVersion, $statusCode, $statusDescription)
  }}
  foreach ($row in $headers) {{
    $rawLines += ('{{0}}: {{1}}' -f $row.name, $row.value)
  }}
  [PSCustomObject]@{{
    method = $MethodName
    status_code = $statusCode
    status_description = $statusDescription
    headers = $headers
    raw_headers = ($rawLines -join "`r`n")
  }} | ConvertTo-Json -Compress -Depth 6
}}
try {{
  $response = Invoke-WebRequest -Uri '{escaped_target}' -Method {escaped_method} -MaximumRedirection 0
  Emit-Result -Response $response -MethodName '{escaped_method}'
}} catch {{
  if ($_.Exception -and $_.Exception.Response) {{
    Emit-Result -Response $_.Exception.Response -MethodName '{escaped_method}'
    exit 0
  }}
  throw
}}
""".strip()
    return [shell_path, "-NoProfile", "-NonInteractive", "-Command", script]


class HTTPSecurityHeadersAdapter:
    name = "http_security_headers"
    capability = "http_security_headers_check"
    noise_score = 2
    cost_score = 2

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        targets = self._collect_targets(context, run_data)[:5]
        if not targets:
            return []
        if os.name == "nt":
            shell_path = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
            return [" ".join(build_windows_head_command(str(item["url"]), shell_path=shell_path)) for item in targets]
        return [" ".join(build_linux_head_command(str(item["url"]))) for item in targets]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        result = AdapterResult()
        config = context.config.get("http_security_headers", {})
        if not isinstance(config, dict):
            config = {}
        if not bool(config.get("enabled", True)):
            started_at = now_utc()
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="http security headers (disabled)",
                    started_at=started_at,
                    ended_at=now_utc(),
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            result.facts["http_security_headers.available"] = False
            return result

        targets = self._collect_targets(context, run_data)
        already_scanned = {
            normalize_url_key(item)
            for item in run_data.facts.get("http_security_headers.scanned_urls", [])
            if normalize_url_key(item)
        }
        targets = [
            target
            for target in targets
            if normalize_url_key(str(target.get("url") or "")) not in already_scanned
        ]
        if not targets:
            started_at = now_utc()
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="http security headers (no new targets)",
                    started_at=started_at,
                    ended_at=now_utc(),
                    status="skipped",
                    execution_id=new_id("exec"),
                    capability=self.capability,
                    exit_code=0,
                )
            )
            result.facts["http_security_headers.available"] = True
            result.facts["http_security_headers.scanned_targets"] = 0
            return result

        timeout_seconds = int(
            config.get("timeout_seconds", context.config.get("scan", {}).get("http_timeout_seconds", 10))
        )
        shell_path = shutil.which("powershell") or shutil.which("pwsh") or "powershell"
        completed_urls: list[str] = []
        affected_urls: list[str] = []
        analyses: list[dict[str, Any]] = []

        for target in targets:
            url = str(target.get("url") or "").strip()
            if not url:
                continue
            if getattr(context, "rate_limiter", None) is not None:
                context.rate_limiter.throttle(
                    target_key=url,
                    service_key=f"service:{target.get('service_id')}" if target.get("service_id") else None,
                )
            command_result, parsed_response, method_used = self._run_probe(
                context,
                url=url,
                timeout_seconds=timeout_seconds,
                shell_path=shell_path,
            )
            result.tool_executions.extend(command_result["tool_executions"])
            result.task_results.extend(command_result["task_results"])
            result.evidence_artifacts.extend(command_result["evidence_artifacts"])
            if parsed_response is None:
                result.warnings.append(f"HTTP security header check did not return usable headers for {url}")
                continue

            analysis = build_header_analysis(
                url=url,
                status_code=parsed_response.status_code,
                headers=parsed_response.headers,
                raw_headers=parsed_response.raw_headers,
            )
            analysis["method_used"] = method_used
            analysis["asset_id"] = str(target.get("asset_id") or "")
            analysis["service_id"] = str(target.get("service_id") or "")
            analysis["webapp_id"] = str(target.get("webapp_id") or "")
            analyses.append(analysis)
            completed_urls.append(url)
            if analysis["trigger_finding"]:
                affected_urls.append(url)

            analysis_path = context.run_store.artifact_path(
                self.name,
                f"http_headers_{_safe_name(url)}.json",
            )
            raw_headers_path = context.run_store.artifact_path(
                self.name,
                f"http_headers_{_safe_name(url)}.txt",
            )
            analysis_path.write_text(json.dumps(analysis, indent=2, sort_keys=True), encoding="utf-8")
            raw_headers_path.write_text(str(parsed_response.raw_headers or ""), encoding="utf-8")

            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="http_response_headers",
                snippet=summarize_analysis(analysis),
                artifact_path=str(analysis_path),
                selector={
                    "kind": "json",
                    "url": url,
                    "status_code": parsed_response.status_code,
                    "raw_headers_path": str(raw_headers_path),
                },
                source_execution_id=command_result["last_execution_id"],
                parser_version=PARSER_VERSION,
                confidence=0.92,
            )
            result.evidence.append(evidence)
            result.evidence_artifacts.extend(
                [
                    EvidenceArtifact(
                        artifact_id=new_id("artifact"),
                        kind="raw",
                        path=str(analysis_path),
                        source_tool=self.name,
                        caption=f"HTTP security header analysis for {url}",
                        source_task_id=command_result["last_task_id"],
                        source_execution_id=command_result["last_execution_id"],
                    ),
                    EvidenceArtifact(
                        artifact_id=new_id("artifact"),
                        kind="raw",
                        path=str(raw_headers_path),
                        source_tool=self.name,
                        caption=f"Raw response headers for {url}",
                        source_task_id=command_result["last_task_id"],
                        source_execution_id=command_result["last_execution_id"],
                    ),
                ]
            )
            entity_type, entity_id = self._resolve_entity(target, run_data)
            evidence_ids = [evidence.evidence_id]
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.http_security_headers.analysis",
                    value=analysis,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    source_tool=self.name,
                    confidence=0.92,
                    evidence_ids=evidence_ids,
                    source_execution_id=command_result["last_execution_id"],
                    parser_version=PARSER_VERSION,
                )
            )
            if analysis["core_missing"]:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.missing_security_headers",
                        value=list(analysis["core_missing"]),
                        entity_type=entity_type,
                        entity_id=entity_id,
                        source_tool=self.name,
                        confidence=0.92,
                        evidence_ids=evidence_ids,
                        source_execution_id=command_result["last_execution_id"],
                        parser_version=PARSER_VERSION,
                    )
                )
            if analysis["core_weak"]:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.weak_security_headers",
                        value=list(analysis["core_weak"]),
                        entity_type=entity_type,
                        entity_id=entity_id,
                        source_tool=self.name,
                        confidence=0.92,
                        evidence_ids=evidence_ids,
                        source_execution_id=command_result["last_execution_id"],
                        parser_version=PARSER_VERSION,
                    )
                )
            context.logger.info(
                "http_security_headers checked url=%s status=%s missing=%s weak=%s method=%s",
                url,
                parsed_response.status_code,
                ",".join(analysis["core_missing"]) or "none",
                ",".join(analysis["core_weak"]) or "none",
                method_used,
            )

        scanned_urls = sorted(
            {
                *(item for item in run_data.facts.get("http_security_headers.scanned_urls", []) if str(item).strip()),
                *completed_urls,
            }
        )
        result.facts["http_security_headers.available"] = True
        result.facts["http_security_headers.scanned_targets"] = len(completed_urls)
        result.facts["http_security_headers.scanned_urls"] = scanned_urls
        result.facts["http_security_headers.affected_urls"] = sorted(set(affected_urls))
        result.facts["http_security_headers.results"] = sorted(analyses, key=lambda item: str(item.get("url") or ""))
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "scanned_targets": len(completed_urls),
                "affected_targets": len(set(affected_urls)),
            },
        )
        return result

    def _collect_targets(self, context: AdapterContext, run_data: RunData) -> list[dict[str, str]]:
        targets: list[dict[str, str]] = []
        seen: set[str] = set()

        def _append(row: dict[str, Any]) -> None:
            url = normalize_url_key(str(row.get("url") or ""))
            if not url or url in seen:
                return
            seen.add(url)
            targets.append(
                {
                    "url": url,
                    "asset_id": str(row.get("asset_id") or ""),
                    "service_id": str(row.get("service_id") or ""),
                    "webapp_id": str(row.get("webapp_id") or ""),
                }
            )

        for target in collect_confirmed_web_targets(run_data):
            _append(target)

        for scope_target in run_data.scope:
            if scope_target.target_type != TargetType.URL:
                continue
            value = str(scope_target.value or "").strip()
            if not value.lower().startswith(("http://", "https://")):
                continue
            _append({"url": value, "asset_id": scope_target.target_id})

        return filter_url_targets_for_task_inputs(context, targets)

    def _resolve_entity(self, target: dict[str, Any], run_data: RunData) -> tuple[str, str]:
        webapp_id = str(target.get("webapp_id") or "").strip()
        if webapp_id:
            return ("web_app", webapp_id)
        url = normalize_url_key(str(target.get("url") or ""))
        for web_app in run_data.web_apps:
            if normalize_url_key(web_app.url) == url:
                return ("web_app", web_app.webapp_id)
        asset_id = str(target.get("asset_id") or "").strip()
        if asset_id:
            return ("asset", asset_id)
        return ("asset", url or new_id("asset"))

    def _run_probe(
        self,
        context: AdapterContext,
        *,
        url: str,
        timeout_seconds: int,
        shell_path: str,
    ) -> tuple[dict[str, Any], ParsedHeaderResponse | None, str]:
        suffix = _safe_name(url)
        tool_executions = []
        task_results = []
        evidence_artifacts = []

        primary_spec = self._command_spec(url=url, suffix=f"{suffix}_head", shell_path=shell_path, fallback=False, timeout_seconds=timeout_seconds)
        primary_result = run_command_spec(context, primary_spec)
        tool_executions.append(primary_result.execution)
        task_results.append(primary_result.task_result)
        evidence_artifacts.extend(primary_result.evidence_artifacts)
        primary_parsed = self._parse_probe_output(primary_result.stdout_text, windows=os.name == "nt")
        if primary_result.task_result.status == "completed" and self._response_is_usable(primary_parsed):
            return (
                {
                    "tool_executions": tool_executions,
                    "task_results": task_results,
                    "evidence_artifacts": evidence_artifacts,
                    "last_execution_id": primary_result.execution.execution_id,
                    "last_task_id": primary_result.task_result.task_id,
                },
                primary_parsed,
                "HEAD",
            )

        fallback_spec = self._command_spec(
            url=url,
            suffix=f"{suffix}_get",
            shell_path=shell_path,
            fallback=True,
            timeout_seconds=timeout_seconds,
        )
        fallback_result = run_command_spec(context, fallback_spec)
        tool_executions.append(fallback_result.execution)
        task_results.append(fallback_result.task_result)
        evidence_artifacts.extend(fallback_result.evidence_artifacts)
        fallback_parsed = self._parse_probe_output(fallback_result.stdout_text, windows=os.name == "nt")
        return (
            {
                "tool_executions": tool_executions,
                "task_results": task_results,
                "evidence_artifacts": evidence_artifacts,
                "last_execution_id": fallback_result.execution.execution_id,
                "last_task_id": fallback_result.task_result.task_id,
            },
            fallback_parsed if self._response_is_usable(fallback_parsed) else None,
            "GET",
        )

    def _command_spec(
        self,
        *,
        url: str,
        suffix: str,
        shell_path: str,
        fallback: bool,
        timeout_seconds: int,
    ) -> CommandSpec:
        if os.name == "nt":
            command = (
                build_windows_fallback_command(url, shell_path=shell_path)
                if fallback
                else build_windows_head_command(url, shell_path=shell_path)
            )
        else:
            command = build_linux_fallback_command(url) if fallback else build_linux_head_command(url)
        return CommandSpec(
            tool_name=self.name,
            capability=self.capability,
            task_type=TASK_TYPE,
            command=command,
            timeout_seconds=timeout_seconds,
            artifact_prefix=f"http_headers_{suffix}",
        )

    def _parse_probe_output(self, stdout_text: str, *, windows: bool) -> ParsedHeaderResponse:
        if windows:
            try:
                payload = json.loads(stdout_text) if str(stdout_text or "").strip() else {}
            except json.JSONDecodeError:
                payload = {}
            headers = normalize_header_map(payload.get("headers", []))
            return ParsedHeaderResponse(
                status_code=int(payload["status_code"]) if payload.get("status_code") is not None else None,
                headers=headers,
                raw_headers=str(payload.get("raw_headers") or ""),
            )
        return parse_raw_response_headers(stdout_text)

    def _response_is_usable(self, parsed_response: ParsedHeaderResponse) -> bool:
        return parsed_response.status_code is not None and bool(parsed_response.headers)
