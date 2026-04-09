from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from collections import defaultdict
from hashlib import sha1
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from attackcastle.adapters.base import build_tool_execution
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import (
    CoverageDecision,
    CoverageGap,
    Evidence,
    Observation,
    PlaybookExecution,
    ProofOutcome,
    ResponseDelta,
    ValidationResult,
    new_id,
    now_utc,
)
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event
from attackcastle.proxy import open_url

DEFAULT_PRESETS: dict[str, list[str]] = {
    "misconfig": ["/swagger.json", "/openapi.json", "/server-status", "/actuator/health", "/actuator/env"],
    "data_exposure": ["/.env", "/backup.zip", "/app.js.map", "/bundle.js.map"],
    "api_idor": ["id", "user", "account", "project", "order", "item"],
    "injection": ["'", "\"", "<attackcastle-xss>"],
    "xss": ["attackcastle_xss_probe"],
    "sqli": ["'", "\""],
    "auth_rate_limit": ["authorization", "set-cookie", "jwt"],
    "upload": [".php", ".jsp", ".aspx"],
    "component": ["jquery", "angularjs", "bootstrap", "vue", "react"],
    "infra": ["access-control-allow-origin", "server", "x-powered-by"],
}
DB_ERROR_PATTERNS = (
    "sql syntax",
    "mysql_fetch",
    "postgresql",
    "sqlite error",
    "odbc sql",
    "unclosed quotation mark",
    "sqlstate",
    "ora-01756",
)
SECRET_PATTERNS = (
    r"(?i)(api[_-]?key|secret|token|client[_-]?secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)bearer\s+[a-z0-9\-_\.]{16,}",
)
RECOMMENDED_SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _coverage_config(config: dict[str, Any]) -> dict[str, Any]:
    coverage = config.get("coverage_engine", {})
    if isinstance(coverage, dict) and coverage:
        return coverage
    fallback = config.get("active_validation", {})
    return fallback if isinstance(fallback, dict) else {}


def _load_preset_entries(path_value: str, defaults: list[str]) -> list[str]:
    candidate = str(path_value or "").strip()
    if not candidate:
        return list(defaults)
    path = Path(candidate).expanduser()
    if not path.exists() or not path.is_file():
        return list(defaults)
    values: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values or list(defaults)


def _family_enabled(config: dict[str, Any], family: str) -> bool:
    families = config.get("families", {})
    if not isinstance(families, dict):
        return True
    family_config = families.get(family, {})
    if not isinstance(family_config, dict):
        return True
    return bool(family_config.get("enabled", True))


def _family_presets(config: dict[str, Any], family: str) -> list[str]:
    families = config.get("families", {})
    family_config = families.get(family, {}) if isinstance(families, dict) else {}
    preset_path = family_config.get("preset_path", "") if isinstance(family_config, dict) else ""
    return _load_preset_entries(str(preset_path or ""), DEFAULT_PRESETS.get(family, []))


def _playbook_enabled(config: dict[str, Any], playbook_key: str) -> bool:
    playbooks = config.get("playbooks", {})
    if not isinstance(playbooks, dict):
        return True
    playbook_config = playbooks.get(playbook_key, {})
    if not isinstance(playbook_config, dict):
        return True
    return bool(playbook_config.get("enabled", True))


def _playbook_for_result(validation_result: ValidationResult) -> str:
    family = str(validation_result.family or "").lower()
    validator_key = str(validation_result.validator_key or "").lower()
    if family in {"api_idor"} or "idor" in validator_key:
        return "object_access"
    if family in {"xss", "sqli", "injection"}:
        return "input_reflection_injection"
    if "admin" in validator_key or "backup" in validator_key:
        return "admin_debug_exposure"
    if family in {"data_exposure", "component"}:
        return "client_artifact_exposure"
    return "api_expansion"


def _build_response_delta(
    *,
    replay_request_id: str,
    attack_path_id: str | None,
    step_key: str,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    evidence_ids: list[str],
    details: dict[str, Any] | None = None,
) -> ResponseDelta:
    baseline_body = str(baseline.get("body_text") or "")
    candidate_body = str(candidate.get("body_text") or "")
    baseline_headers = {str(k).lower(): v for k, v in dict(baseline.get("headers") or {}).items()}
    candidate_headers = {str(k).lower(): v for k, v in dict(candidate.get("headers") or {}).items()}
    changed_headers = {
        key: {"before": baseline_headers.get(key), "after": candidate_headers.get(key)}
        for key in sorted(set([*baseline_headers.keys(), *candidate_headers.keys()]))
        if baseline_headers.get(key) != candidate_headers.get(key)
    }
    return ResponseDelta(
        response_delta_id=new_id("delta"),
        replay_request_id=replay_request_id,
        attack_path_id=attack_path_id or "",
        step_key=step_key,
        protocol_family="http",
        interaction_target=str(candidate.get("final_url") or baseline.get("final_url") or ""),
        comparison_type="baseline_vs_mutated",
        summary=f"HTTP {baseline.get('status_code')} -> {candidate.get('status_code')} | length {len(baseline_body)} -> {len(candidate_body)}",
        status_before=baseline.get("status_code"),
        status_after=candidate.get("status_code"),
        body_changed=baseline_body != candidate_body,
        header_changed=bool(changed_headers),
        length_before=len(baseline_body),
        length_after=len(candidate_body),
        length_delta=len(candidate_body) - len(baseline_body),
        evidence_ids=list(evidence_ids),
        header_deltas=changed_headers,
        details=dict(details or {}),
        source_tool="active_validation",
        parser_version="active_validation_v2",
    )


def _fetch_exchange(
    url: str,
    *,
    timeout_seconds: int,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    proxy_url: str | None = None,
    response_capture_bytes: int = 262144,
) -> dict[str, Any]:
    request = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    ssl_context = ssl._create_unverified_context() if url.startswith("https://") else None
    try:
        with open_url(
            request,
            timeout=timeout_seconds,
            proxy_url=proxy_url,
            https_context=ssl_context,
        ) as response:
            payload = response.read(max(1024, response_capture_bytes))
            return {
                "status_code": response.getcode(),
                "headers": {key.lower(): value for key, value in response.headers.items()},
                "body_text": payload.decode("utf-8", errors="ignore"),
                "final_url": response.geturl() or url,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        payload = exc.read(max(1024, response_capture_bytes))
        return {
            "status_code": exc.code,
            "headers": {key.lower(): value for key, value in exc.headers.items()},
            "body_text": payload.decode("utf-8", errors="ignore"),
            "final_url": exc.geturl() or url,
            "error": f"http_error:{exc.code}",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status_code": None,
            "headers": {},
            "body_text": "",
            "final_url": url,
            "error": str(exc),
        }


def _append_or_replace_query(url: str, parameter_name: str, value: str) -> str:
    parsed = urlsplit(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    next_pairs: list[tuple[str, str]] = []
    for name, current_value in query_pairs:
        if name == parameter_name and not replaced:
            next_pairs.append((name, value))
            replaced = True
        else:
            next_pairs.append((name, current_value))
    if not replaced:
        next_pairs.append((parameter_name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(next_pairs, doseq=True), parsed.fragment))


def _record_validation_artifact(
    context: AdapterContext,
    *,
    adapter_name: str,
    validator_key: str,
    url: str,
    request_summary: dict[str, Any],
    response_summary: dict[str, Any],
    mutated_url: str | None = None,
) -> str:
    file_name = f"{validator_key}_{_safe_name((mutated_url or url) + validator_key)}.json"
    artifact_path = context.run_store.artifact_path(adapter_name, file_name)
    artifact_path.write_text(
        json.dumps(
            {
                "request": request_summary,
                "response": response_summary,
                "mutated_url": mutated_url,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(artifact_path)


class ActiveValidationAdapter:
    name = "active_validation"
    capability = "active_validation_core"
    noise_score = 4
    cost_score = 5

    def preview_commands(self, context: AdapterContext, run_data) -> list[str]:
        return [f"validate replay request {item.url}" for item in getattr(run_data, "replay_requests", [])[:15]]

    def _validation_enabled_families(self, mode: str, config: dict[str, Any]) -> list[str]:
        families = ["misconfig", "data_exposure", "api_idor", "component", "infra"]
        if mode == "aggressive":
            families.extend(["xss", "sqli", "injection", "auth_rate_limit"])
        return [family for family in families if _family_enabled(config, family)]

    def _result(
        self,
        *,
        replay_request: Any,
        attack_path_id: str | None = None,
        playbook_key: str = "",
        step_key: str = "",
        entry_signal_ids: list[str] | None = None,
        validator_key: str,
        family: str,
        category: str,
        status: str,
        title: str,
        summary: str,
        severity_hint: str,
        confidence: float,
        evidence_ids: list[str],
        tags: list[str],
        details: dict[str, Any],
        response_delta: dict[str, Any] | None = None,
        stop_reason: str = "",
        proof_strength: str = "medium",
        execution_id: str,
    ) -> ValidationResult:
        return ValidationResult(
            validation_result_id=new_id("vresult"),
            replay_request_id=replay_request.replay_request_id,
            webapp_id=replay_request.webapp_id,
            validator_key=validator_key,
            family=family,
            category=category,
            status=status,
            title=title,
            summary=summary,
            entity_type="web_app",
            entity_id=replay_request.webapp_id,
            service_id=replay_request.service_id,
            protocol_family="http",
            severity_hint=severity_hint,
            request_url=replay_request.url,
            request_method=replay_request.method,
            mutated=bool(details.get("mutated")),
            confidence=confidence,
            coverage_lane_id=attack_path_id,
            attack_path_id=attack_path_id,
            playbook_key=playbook_key,
            step_key=step_key,
            entry_signal_ids=list(entry_signal_ids or []),
            response_delta=dict(response_delta or {}),
            stop_reason=stop_reason,
            proof_strength=proof_strength,
            evidence_ids=evidence_ids,
            tags=tags,
            details=details,
            source_tool=self.name,
            source_execution_id=execution_id,
            parser_version="active_validation_v2",
        )

    def run(self, context: AdapterContext, run_data) -> AdapterResult:
        started_at = now_utc()
        execution_id = new_id("exec")
        result = AdapterResult()
        config = _coverage_config(context.config)
        mode = str(config.get("mode", "safe-active")).strip().lower() or "safe-active"
        replay_enabled = bool(config.get("request_replay_enabled", True))
        if not replay_enabled:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="active validation (request replay disabled)",
                    started_at=started_at,
                    ended_at=now_utc(),
                    status="skipped",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=0,
                )
            )
            result.facts["active_validation.mode"] = mode
            result.facts["active_validation.coverage_gaps"] = []
            result.facts["coverage_engine.mode"] = mode
            result.facts["coverage_engine.coverage_gaps"] = []
            return result

        timeout_seconds = int(config.get("timeout_seconds", 10))
        per_target_budget = int(config.get("per_target_budget", 6))
        response_capture_bytes = int(config.get("response_capture_bytes", 262144))
        user_agent = str(
            context.config.get("scan", {}).get(
                "user_agent",
                "AttackCastle/0.1 (+authorized-security-assessment)",
            )
        )
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip() or None
        replay_requests = list(getattr(run_data, "replay_requests", []) or [])
        attack_paths = list(getattr(run_data, "attack_paths", []) or [])
        investigation_steps = list(getattr(run_data, "investigation_steps", []) or [])
        path_by_id = {item.attack_path_id: item for item in attack_paths}
        steps_by_path: defaultdict[str, list[Any]] = defaultdict(list)
        for item in investigation_steps:
            steps_by_path[item.attack_path_id].append(item)
        playbooks_by_webapp: defaultdict[str, list[tuple[Any, Any]]] = defaultdict(list)
        for attack_path in attack_paths:
            webapp_id = ""
            for entity in attack_path.affected_entities:
                if entity.get("entity_type") == "web_app":
                    webapp_id = str(entity.get("entity_id") or "")
                    break
            if not webapp_id:
                continue
            for step in steps_by_path.get(attack_path.attack_path_id, []):
                if step.status == "planned" and bool(step.details.get("fallback")):
                    continue
                playbooks_by_webapp[webapp_id].append((attack_path, step))
        if not replay_requests:
            result.tool_executions.append(
                build_tool_execution(
                    tool_name=self.name,
                    command="active validation (no replay requests)",
                    started_at=started_at,
                    ended_at=now_utc(),
                    status="skipped",
                    execution_id=execution_id,
                    capability=self.capability,
                    exit_code=0,
                )
            )
            result.facts["active_validation.mode"] = mode
            result.facts["active_validation.coverage_gaps"] = []
            result.facts["coverage_engine.mode"] = mode
            result.facts["coverage_engine.coverage_gaps"] = []
            return result

        by_webapp_budget: defaultdict[str, int] = defaultdict(int)
        coverage_gaps: list[dict[str, Any]] = []
        validation_counts: defaultdict[str, int] = defaultdict(int)
        enabled_families = self._validation_enabled_families(mode, config)
        raw_artifact_paths: list[str] = []

        for replay_request in replay_requests:
            if by_webapp_budget[replay_request.webapp_id] >= per_target_budget:
                continue
            request_result_start = len(result.validation_results)
            request_proof_start = len(result.proof_outcomes)
            request_delta_start = len(result.response_deltas)
            base_headers = dict(replay_request.headers or {})
            base_headers.setdefault("User-Agent", user_agent)
            base_headers.setdefault("Accept", "*/*")
            base_response = _fetch_exchange(
                replay_request.url,
                timeout_seconds=timeout_seconds,
                method=replay_request.method or "GET",
                headers=base_headers,
                proxy_url=proxy_url,
                response_capture_bytes=response_capture_bytes,
            )
            if base_response.get("status_code") is None:
                gap = {
                    "url": replay_request.url,
                    "reason": "request replay failed",
                    "impact": "Active validation could not obtain a baseline response for this request.",
                    "suggested_action": "Retry manually through the replay inspector or a proxy-assisted workflow.",
                    "mode": mode,
                }
                coverage_gaps.append(gap)
                result.coverage_gaps.append(
                    CoverageGap(
                        coverage_gap_id=new_id("gap"),
                        title="Replay baseline unavailable",
                        source=self.name,
                        reason=str(gap["reason"]),
                        impact=str(gap["impact"]),
                        suggested_action=str(gap["suggested_action"]),
                        url=replay_request.url,
                        affected_entities=[{"entity_type": "web_app", "entity_id": replay_request.webapp_id}],
                        source_tool=self.name,
                    )
                )
                continue

            request_plans = sorted(
                playbooks_by_webapp.get(replay_request.webapp_id, []),
                key=lambda item: getattr(item[0], "priority_score", 0),
                reverse=True,
            )
            playbook_plan = {path.playbook_key: (path, step) for path, step in request_plans}
            enabled_request_playbooks = {
                key
                for key, (_path, step) in playbook_plan.items()
                if _playbook_enabled(config, key) and (step.auto_runnable or mode == "aggressive")
            }
            if not enabled_request_playbooks:
                if any(tag in replay_request.tags for tag in {"docs", "api", "graphql"}):
                    enabled_request_playbooks.add("api_expansion")
                if "admin" in replay_request.tags or "backup" in replay_request.tags:
                    enabled_request_playbooks.add("admin_debug_exposure")
                if "javascript" in replay_request.tags:
                    enabled_request_playbooks.add("client_artifact_exposure")
                if replay_request.parameter_names:
                    enabled_request_playbooks.add("input_reflection_injection")
                if (replay_request.context or {}).get("object_hints") or any(
                    name.lower() in {"id", "user", "account", "order", "item", "project"}
                    for name in replay_request.parameter_names
                ):
                    enabled_request_playbooks.add("object_access")

            def add_evidence(kind: str, snippet: str, request_summary: dict[str, Any], response_summary: dict[str, Any], *, mutated_url: str | None = None) -> str:
                artifact_path = _record_validation_artifact(
                    context,
                    adapter_name=self.name,
                    validator_key=kind,
                    url=replay_request.url,
                    request_summary=request_summary,
                    response_summary=response_summary,
                    mutated_url=mutated_url,
                )
                raw_artifact_paths.append(artifact_path)
                evidence = Evidence(
                    evidence_id=new_id("evidence"),
                    source_tool=self.name,
                    kind="request_replay_validation",
                    snippet=snippet[:380],
                    artifact_path=artifact_path,
                    selector={"kind": "replay_request", "url": replay_request.url, "validator": kind},
                    source_execution_id=execution_id,
                    parser_version="active_validation_v1",
                    confidence=0.86,
                )
                result.evidence.append(evidence)
                emit_entity_event(context, "evidence", evidence, source=self.name)
                emit_artifact_event(
                    context,
                    artifact_path=artifact_path,
                    kind="request_replay_validation",
                    source_tool=self.name,
                    caption=snippet[:120],
                )
                return evidence.evidence_id

            if "docs" in replay_request.tags and base_response.get("status_code") == 200 and "api_expansion" in enabled_request_playbooks:
                evidence_id = add_evidence(
                    "api_docs",
                    f"API documentation or schema surfaced at {replay_request.url}",
                    {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                    base_response,
                )
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.api.docs.exposed",
                        value={"url": replay_request.url, "status_code": base_response.get("status_code")},
                        entity_type="web_app",
                        entity_id=replay_request.webapp_id,
                        source_tool=self.name,
                        confidence=0.84,
                        evidence_ids=[evidence_id],
                        source_execution_id=execution_id,
                        parser_version="active_validation_v1",
                    )
                )
                result.validation_results.append(
                    self._result(
                        replay_request=replay_request,
                        validator_key="api_docs",
                        family="misconfig",
                        category="surface",
                        status="confirmed",
                        title="Exposed API documentation or schema",
                        summary="A documentation, schema, or collection-style route responded successfully without authentication.",
                        severity_hint="medium",
                        confidence=0.84,
                        evidence_ids=[evidence_id],
                        tags=["api", "docs", "surface"],
                        details={"status_code": base_response.get("status_code")},
                        execution_id=execution_id,
                    )
                )
                validation_counts["confirmed"] += 1

            if "admin" in replay_request.tags and base_response.get("status_code") == 200 and "admin_debug_exposure" in enabled_request_playbooks:
                evidence_id = add_evidence(
                    "admin_surface",
                    f"Administrative-looking surface reachable at {replay_request.url}",
                    {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                    base_response,
                )
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.admin_interface",
                        value={"url": replay_request.url, "status_code": base_response.get("status_code")},
                        entity_type="web_app",
                        entity_id=replay_request.webapp_id,
                        source_tool=self.name,
                        confidence=0.83,
                        evidence_ids=[evidence_id],
                        source_execution_id=execution_id,
                        parser_version="active_validation_v1",
                    )
                )
                result.validation_results.append(
                    self._result(
                        replay_request=replay_request,
                        validator_key="admin_surface",
                        family="misconfig",
                        category="surface",
                        status="confirmed",
                        title="Exposed administrative interface",
                        summary="An administrative or management route responded successfully without authentication.",
                        severity_hint="high",
                        confidence=0.83,
                        evidence_ids=[evidence_id],
                        tags=["admin", "surface", "misconfiguration"],
                        details={"status_code": base_response.get("status_code")},
                        execution_id=execution_id,
                    )
                )
                validation_counts["confirmed"] += 1

            if "backup" in replay_request.tags and base_response.get("status_code") == 200 and {"admin_debug_exposure", "client_artifact_exposure"} & enabled_request_playbooks:
                evidence_id = add_evidence(
                    "public_backup",
                    f"Publicly reachable backup or sensitive file at {replay_request.url}",
                    {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                    base_response,
                )
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.public_files",
                        value=[
                            {
                                "path": urlsplit(replay_request.url).path or replay_request.url,
                                "classification": "Backup or exposed file reachable",
                                "status_code": base_response.get("status_code"),
                            }
                        ],
                        entity_type="web_app",
                        entity_id=replay_request.webapp_id,
                        source_tool=self.name,
                        confidence=0.82,
                        evidence_ids=[evidence_id],
                        source_execution_id=execution_id,
                        parser_version="active_validation_v1",
                    )
                )
                result.validation_results.append(
                    self._result(
                        replay_request=replay_request,
                        validator_key="public_backup",
                        family="data_exposure",
                        category="exposure",
                        status="confirmed",
                        title="Publicly exposed sensitive or backup file",
                        summary="A backup, environment, or source-map style file was reachable without authentication.",
                        severity_hint="high",
                        confidence=0.82,
                        evidence_ids=[evidence_id],
                        tags=["backup", "exposure", "public-file"],
                        details={"status_code": base_response.get("status_code")},
                        execution_id=execution_id,
                    )
                )
                validation_counts["confirmed"] += 1

            if ("infra" in enabled_families or "misconfig" in enabled_families) and "api_expansion" in enabled_request_playbooks:
                headers = {key.lower(): str(value) for key, value in dict(base_response.get("headers") or {}).items()}
                missing_headers = [name for name in RECOMMENDED_SECURITY_HEADERS if name not in headers]
                if "misconfig" in enabled_families and missing_headers:
                    evidence_id = add_evidence(
                        "missing_headers",
                        f"Missing recommended security headers on {replay_request.url}",
                        {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                        base_response,
                    )
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.missing_security_headers",
                            value=missing_headers,
                            entity_type="web_app",
                            entity_id=replay_request.webapp_id,
                            source_tool=self.name,
                            confidence=0.82,
                            evidence_ids=[evidence_id],
                            source_execution_id=execution_id,
                            parser_version="active_validation_v1",
                        )
                    )
                    result.validation_results.append(
                        self._result(
                            replay_request=replay_request,
                            validator_key="missing_headers",
                            family="misconfig",
                            category="headers",
                            status="confirmed",
                            title="Missing recommended security headers",
                            summary="The baseline HTTP response omitted one or more common browser hardening headers.",
                            severity_hint="medium",
                            confidence=0.82,
                            evidence_ids=[evidence_id],
                            tags=["headers", "hardening", "misconfiguration"],
                            details={"missing_headers": missing_headers},
                            execution_id=execution_id,
                        )
                    )
                    validation_counts["confirmed"] += 1
                allow_origin = headers.get("access-control-allow-origin", "")
                allow_credentials = headers.get("access-control-allow-credentials", "")
                if allow_origin == "*" or allow_origin.lower() == "https://attackcastle.invalid":
                    evidence_id = add_evidence(
                        "cors",
                        f"CORS misconfiguration observed on {replay_request.url}",
                        {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                        base_response,
                    )
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.cors.misconfigured",
                            value={"allow_origin": allow_origin, "allow_credentials": allow_credentials},
                            entity_type="web_app",
                            entity_id=replay_request.webapp_id,
                            source_tool=self.name,
                            confidence=0.9,
                            evidence_ids=[evidence_id],
                            source_execution_id=execution_id,
                            parser_version="active_validation_v1",
                        )
                    )
                    result.validation_results.append(
                        self._result(
                            replay_request=replay_request,
                            validator_key="cors",
                            family="infra",
                            category="misconfiguration",
                            status="confirmed",
                            title="Misconfigured CORS policy",
                            summary="Cross-origin response headers indicate wildcard or reflected cross-origin access.",
                            severity_hint="high",
                            confidence=0.9,
                            evidence_ids=[evidence_id],
                            tags=["cors", "headers", "misconfiguration"],
                            details={"allow_origin": allow_origin, "allow_credentials": allow_credentials},
                            execution_id=execution_id,
                        )
                    )
                    validation_counts["confirmed"] += 1

            if "misconfig" in enabled_families and "api_expansion" in enabled_request_playbooks:
                options_response = _fetch_exchange(
                    replay_request.url,
                    timeout_seconds=timeout_seconds,
                    method="OPTIONS",
                    headers=base_headers,
                    proxy_url=proxy_url,
                    response_capture_bytes=response_capture_bytes,
                )
                allow_header = str(dict(options_response.get("headers") or {}).get("allow", ""))
                risky_methods = [
                    method_name
                    for method_name in ["PUT", "DELETE", "TRACE", "PATCH"]
                    if method_name in allow_header.upper()
                ]
                if risky_methods:
                    evidence_id = add_evidence(
                        "methods",
                        f"Permissive HTTP methods observed on {replay_request.url}",
                        {"method": "OPTIONS", "url": replay_request.url, "headers": base_headers},
                        options_response,
                    )
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.http_methods.permissive",
                            value=risky_methods,
                            entity_type="web_app",
                            entity_id=replay_request.webapp_id,
                            source_tool=self.name,
                            confidence=0.88,
                            evidence_ids=[evidence_id],
                            source_execution_id=execution_id,
                            parser_version="active_validation_v1",
                        )
                    )
                    result.validation_results.append(
                        self._result(
                            replay_request=replay_request,
                            validator_key="methods",
                            family="misconfig",
                            category="surface",
                            status="confirmed",
                            title="Overly permissive HTTP methods",
                            summary="An OPTIONS response advertised potentially dangerous methods on an unauthenticated surface.",
                            severity_hint="medium",
                            confidence=0.88,
                            evidence_ids=[evidence_id],
                            tags=["methods", "options", "misconfiguration"],
                            details={"allow": allow_header, "risky_methods": risky_methods},
                            execution_id=execution_id,
                        )
                    )
                    validation_counts["confirmed"] += 1

            if "misconfig" in enabled_families and "graphql" in replay_request.tags and "api_expansion" in enabled_request_playbooks:
                gql_query = json.dumps({"query": "{__schema{queryType{name}}}"}, separators=(",", ":")).encode("utf-8")
                gql_headers = {**base_headers, "Content-Type": "application/json", "Origin": "https://attackcastle.invalid"}
                gql_response = _fetch_exchange(
                    replay_request.url,
                    timeout_seconds=timeout_seconds,
                    method="POST",
                    headers=gql_headers,
                    data=gql_query,
                    proxy_url=proxy_url,
                    response_capture_bytes=response_capture_bytes,
                )
                if gql_response.get("status_code") == 200 and "__schema" in str(gql_response.get("body_text") or ""):
                    evidence_id = add_evidence(
                        "graphql_introspection",
                        f"GraphQL introspection enabled on {replay_request.url}",
                        {"method": "POST", "url": replay_request.url, "headers": gql_headers, "body": gql_query.decode("utf-8")},
                        gql_response,
                    )
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.graphql.introspection_enabled",
                            value=True,
                            entity_type="web_app",
                            entity_id=replay_request.webapp_id,
                            source_tool=self.name,
                            confidence=0.92,
                            evidence_ids=[evidence_id],
                            source_execution_id=execution_id,
                            parser_version="active_validation_v1",
                        )
                    )
                    result.validation_results.append(
                        self._result(
                            replay_request=replay_request,
                            validator_key="graphql_introspection",
                            family="misconfig",
                            category="api",
                            status="confirmed",
                            title="GraphQL introspection enabled",
                            summary="An unauthenticated GraphQL endpoint returned schema metadata.",
                            severity_hint="medium",
                            confidence=0.92,
                            evidence_ids=[evidence_id],
                            tags=["graphql", "api", "metadata"],
                            details={"introspection": True},
                            execution_id=execution_id,
                        )
                    )
                    validation_counts["confirmed"] += 1

            if "data_exposure" in enabled_families and "javascript" in replay_request.tags and "client_artifact_exposure" in enabled_request_playbooks:
                body_text = str(base_response.get("body_text") or "")
                secret_matches: list[str] = []
                for pattern in SECRET_PATTERNS:
                    match = re.search(pattern, body_text)
                    if match:
                        secret_matches.append(match.group(0)[:120])
                if secret_matches:
                    evidence_id = add_evidence(
                        "js_secrets",
                        f"Potential secrets exposed in JavaScript at {replay_request.url}",
                        {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                        base_response,
                    )
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.js.sensitive_strings",
                            value=secret_matches,
                            entity_type="web_app",
                            entity_id=replay_request.webapp_id,
                            source_tool=self.name,
                            confidence=0.84,
                            evidence_ids=[evidence_id],
                            source_execution_id=execution_id,
                            parser_version="active_validation_v1",
                        )
                    )
                    result.validation_results.append(
                        self._result(
                            replay_request=replay_request,
                            validator_key="js_secrets",
                            family="data_exposure",
                            category="code_exposure",
                            status="confirmed",
                            title="Sensitive data exposed in client-side JavaScript",
                            summary="Client-side JavaScript contained token- or secret-like material.",
                            severity_hint="high",
                            confidence=0.84,
                            evidence_ids=[evidence_id],
                            tags=["javascript", "secret", "exposure"],
                            details={"matches": secret_matches},
                            execution_id=execution_id,
                        )
                    )
                    validation_counts["confirmed"] += 1

            if "component" in enabled_families:
                outdated_tokens = [
                    observation.value
                    for observation in run_data.observations
                    if observation.entity_type == "web_app"
                    and observation.entity_id == replay_request.webapp_id
                    and observation.key == "web.outdated_library"
                ]
                if outdated_tokens:
                    result.validation_results.append(
                        self._result(
                            replay_request=replay_request,
                            validator_key="outdated_library",
                            family="component",
                            category="component",
                            status="candidate",
                            title="Potential outdated front-end library detected",
                            summary="Fingerprinting suggests a front-end library version that should be reviewed against supported versions and CVEs.",
                            severity_hint="medium",
                            confidence=0.72,
                            evidence_ids=[],
                            tags=["component", "library", "candidate"],
                            details={"libraries": outdated_tokens},
                            execution_id=execution_id,
                        )
                    )
                    validation_counts["candidate"] += 1

            if "api_idor" in enabled_families and "object_access" in enabled_request_playbooks:
                parsed = urlsplit(replay_request.url)
                query_names = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
                candidate_param = next(
                    (
                        name
                        for name in query_names
                        if name.lower() in _family_presets(config, "api_idor")
                    ),
                    "",
                )
                if candidate_param:
                    candidate_value = dict(parse_qsl(parsed.query, keep_blank_values=True)).get(candidate_param, "")
                    if candidate_value.isdigit():
                        mutated_url = _append_or_replace_query(replay_request.url, candidate_param, str(int(candidate_value) + 1))
                        mutated_response = _fetch_exchange(
                            mutated_url,
                            timeout_seconds=timeout_seconds,
                            method=replay_request.method or "GET",
                            headers=base_headers,
                            proxy_url=proxy_url,
                            response_capture_bytes=response_capture_bytes,
                        )
                        if base_response.get("status_code") == 200 and mutated_response.get("status_code") == 200:
                            evidence_id = add_evidence(
                                "idor_candidate",
                                f"Cross-object replay candidate identified on {replay_request.url}",
                                {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                                mutated_response,
                                mutated_url=mutated_url,
                            )
                            result.observations.append(
                                Observation(
                                    observation_id=new_id("obs"),
                                    key="web.idor.candidate",
                                    value={
                                        "parameter": candidate_param,
                                        "base_url": replay_request.url,
                                        "mutated_url": mutated_url,
                                    },
                                    entity_type="web_app",
                                    entity_id=replay_request.webapp_id,
                                    source_tool=self.name,
                                    confidence=0.66,
                                    evidence_ids=[evidence_id],
                                    source_execution_id=execution_id,
                                    parser_version="active_validation_v1",
                                )
                            )
                            result.validation_results.append(
                                self._result(
                                    replay_request=replay_request,
                                    validator_key="idor_candidate",
                                    family="api_idor",
                                    category="access_control",
                                    status="candidate",
                                    title="Potential IDOR/BOLA candidate",
                                    summary="Neighbor-object replay returned a successful response and should be manually reviewed for authorization boundaries.",
                                    severity_hint="high",
                                    confidence=0.66,
                                    evidence_ids=[evidence_id],
                                    tags=["idor", "bola", "candidate"],
                                    details={"parameter": candidate_param, "mutated_url": mutated_url, "mutated": True},
                                    execution_id=execution_id,
                                )
                            )
                            validation_counts["candidate"] += 1

            if mode == "aggressive" and "xss" in enabled_families and "input_reflection_injection" in enabled_request_playbooks:
                for parameter_name in list(replay_request.parameter_names or [])[:3]:
                    marker = f"attackcastle_xss_{_safe_name(replay_request.url + parameter_name)}"
                    mutated_url = _append_or_replace_query(replay_request.url, parameter_name, marker)
                    mutated_response = _fetch_exchange(
                        mutated_url,
                        timeout_seconds=timeout_seconds,
                        method=replay_request.method or "GET",
                        headers=base_headers,
                        proxy_url=proxy_url,
                        response_capture_bytes=response_capture_bytes,
                    )
                    if marker in str(mutated_response.get("body_text") or ""):
                        evidence_id = add_evidence(
                            "reflected_xss",
                            f"Reflected input observed for {parameter_name} on {replay_request.url}",
                            {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                            mutated_response,
                            mutated_url=mutated_url,
                        )
                        result.observations.append(
                            Observation(
                                observation_id=new_id("obs"),
                                key="web.xss.reflected",
                                value={"parameter": parameter_name, "marker": marker},
                                entity_type="web_app",
                                entity_id=replay_request.webapp_id,
                                source_tool=self.name,
                                confidence=0.88,
                                evidence_ids=[evidence_id],
                                source_execution_id=execution_id,
                                parser_version="active_validation_v1",
                            )
                        )
                        result.validation_results.append(
                            self._result(
                                replay_request=replay_request,
                                validator_key="reflected_xss",
                                family="xss",
                                category="injection",
                                status="confirmed",
                                title="Reflected XSS signal observed",
                                summary="A replay mutation was reflected in the HTTP response body.",
                                severity_hint="high",
                                confidence=0.88,
                                evidence_ids=[evidence_id],
                                tags=["xss", "reflected", "mutated-request"],
                                details={"parameter": parameter_name, "marker": marker, "mutated": True},
                                execution_id=execution_id,
                            )
                        )
                        validation_counts["confirmed"] += 1
                        break

            if mode == "aggressive" and ("sqli" in enabled_families or "injection" in enabled_families) and "input_reflection_injection" in enabled_request_playbooks:
                for parameter_name in list(replay_request.parameter_names or [])[:3]:
                    mutated_url = _append_or_replace_query(replay_request.url, parameter_name, "'")
                    mutated_response = _fetch_exchange(
                        mutated_url,
                        timeout_seconds=timeout_seconds,
                        method=replay_request.method or "GET",
                        headers=base_headers,
                        proxy_url=proxy_url,
                        response_capture_bytes=response_capture_bytes,
                    )
                    lowered_body = str(mutated_response.get("body_text") or "").lower()
                    if any(token in lowered_body for token in DB_ERROR_PATTERNS):
                        evidence_id = add_evidence(
                            "sqli_error",
                            f"SQL error response observed for {parameter_name} on {replay_request.url}",
                            {"method": replay_request.method, "url": replay_request.url, "headers": base_headers},
                            mutated_response,
                            mutated_url=mutated_url,
                        )
                        result.observations.append(
                            Observation(
                                observation_id=new_id("obs"),
                                key="web.sqli.error_based",
                                value={"parameter": parameter_name, "mutated_url": mutated_url},
                                entity_type="web_app",
                                entity_id=replay_request.webapp_id,
                                source_tool=self.name,
                                confidence=0.86,
                                evidence_ids=[evidence_id],
                                source_execution_id=execution_id,
                                parser_version="active_validation_v1",
                            )
                        )
                        result.validation_results.append(
                            self._result(
                                replay_request=replay_request,
                                validator_key="sqli_error",
                                family="sqli",
                                category="injection",
                                status="confirmed",
                                title="Error-based SQL injection signal observed",
                                summary="A replay mutation produced a database-style error response.",
                                severity_hint="critical",
                                confidence=0.86,
                                evidence_ids=[evidence_id],
                                tags=["sqli", "injection", "error-based"],
                                details={"parameter": parameter_name, "mutated_url": mutated_url, "mutated": True},
                                execution_id=execution_id,
                            )
                        )
                        validation_counts["confirmed"] += 1
                        break

            for validation_result in result.validation_results[request_result_start:]:
                if validation_result.playbook_key:
                    continue
                playbook_key = _playbook_for_result(validation_result)
                attack_path, step = playbook_plan.get(playbook_key, (None, None))
                synthetic_attack_path_id = None
                if attack_path is None:
                    synthetic_attack_path_id = f"synthetic-{playbook_key}-{replay_request.webapp_id}"
                validation_result.playbook_key = playbook_key
                validation_result.attack_path_id = (
                    attack_path.attack_path_id
                    if attack_path is not None
                    else synthetic_attack_path_id
                )
                validation_result.step_key = (
                    step.step_key
                    if step is not None
                    else (validation_result.step_key or validation_result.validator_key)
                )
                validation_result.entry_signal_ids = (
                    list(attack_path.entry_signal_ids) if attack_path is not None else list(validation_result.entry_signal_ids)
                )
                validation_result.stop_reason = validation_result.stop_reason or (
                    "explicit proof captured"
                    if validation_result.status == "confirmed"
                    else "candidate signal requires analyst review"
                )
                validation_result.proof_strength = (
                    "strong" if validation_result.status == "confirmed" else validation_result.proof_strength
                )
                if attack_path is not None:
                    delta = _build_response_delta(
                        replay_request_id=replay_request.replay_request_id,
                        attack_path_id=attack_path.attack_path_id,
                        step_key=validation_result.step_key,
                        baseline=base_response,
                        candidate=validation_result.details.get("mutated_response", base_response),
                        evidence_ids=list(validation_result.evidence_ids),
                        details={"validator_key": validation_result.validator_key},
                    )
                    if validation_result.mutated:
                        validation_result.response_delta = {
                            "summary": delta.summary,
                            "status_before": delta.status_before,
                            "status_after": delta.status_after,
                            "length_delta": delta.length_delta,
                            "body_changed": delta.body_changed,
                        }
                        result.response_deltas.append(delta)
                elif validation_result.mutated:
                    delta = _build_response_delta(
                        replay_request_id=replay_request.replay_request_id,
                        attack_path_id=synthetic_attack_path_id,
                        step_key=validation_result.step_key,
                        baseline=base_response,
                        candidate=base_response,
                        evidence_ids=list(validation_result.evidence_ids),
                        details={"validator_key": validation_result.validator_key, "synthetic": True},
                    )
                    validation_result.response_delta = {
                        "summary": delta.summary,
                        "status_before": delta.status_before,
                        "status_after": delta.status_after,
                        "length_delta": delta.length_delta,
                        "body_changed": delta.body_changed,
                    }
                    result.response_deltas.append(delta)
                result.proof_outcomes.append(
                    ProofOutcome(
                        proof_outcome_id=new_id("proof"),
                        attack_path_id=validation_result.attack_path_id or "",
                        playbook_key=validation_result.playbook_key,
                        step_key=validation_result.step_key,
                        status=validation_result.status,
                        reason=validation_result.stop_reason or validation_result.summary,
                        strength=validation_result.proof_strength,
                        validation_result_id=validation_result.validation_result_id,
                        evidence_ids=list(validation_result.evidence_ids),
                        details={"validator_key": validation_result.validator_key},
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="active_validation_v2",
                    )
                )
            for attack_path, step in request_plans:
                relevant_results = [
                    item
                    for item in result.validation_results[request_result_start:]
                    if item.attack_path_id == attack_path.attack_path_id
                ]
                if not relevant_results:
                    continue
                latest = relevant_results[-1]
                coverage_status = "completed" if latest.status == "confirmed" else "candidate"
                decision = CoverageDecision(
                    coverage_decision_id=new_id("coverage"),
                    attack_path_id=attack_path.attack_path_id,
                    playbook_key=attack_path.playbook_key,
                    status=coverage_status,
                    reason=latest.stop_reason or latest.summary,
                    next_action="Preserve proof and report." if latest.status == "confirmed" else attack_path.next_action,
                    evidence_ids=list(latest.evidence_ids),
                    details={"step_key": step.step_key, "validator_key": latest.validator_key},
                    source_tool=self.name,
                    source_execution_id=execution_id,
                    parser_version="active_validation_v2",
                )
                result.coverage_decisions.append(decision)
                result.playbook_executions.append(
                    PlaybookExecution(
                        playbook_execution_id=new_id("playbook"),
                        attack_path_id=attack_path.attack_path_id,
                        playbook_key=attack_path.playbook_key,
                        status=coverage_status,
                        entry_signal_ids=list(attack_path.entry_signal_ids),
                        executed_step_ids=[step.investigation_step_id],
                        next_step_id=None if latest.status == "confirmed" else attack_path.next_step_id,
                        proof_outcome_id=result.proof_outcomes[-1].proof_outcome_id if result.proof_outcomes else None,
                        summary=latest.summary,
                        coverage_decision_id=decision.coverage_decision_id,
                        evidence_ids=list(latest.evidence_ids),
                        details={"validator_key": latest.validator_key},
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="active_validation_v2",
                    )
                )

            by_webapp_budget[replay_request.webapp_id] += 1

        for coverage_gap in result.coverage_gaps:
            emit_entity_event(context, "coverage_gap", coverage_gap, source=self.name)
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="coverage.gap",
                    value={
                        "reason": coverage_gap.reason,
                        "impact": coverage_gap.impact,
                        "suggested_action": coverage_gap.suggested_action,
                        "url": coverage_gap.url,
                        "mode": mode,
                    },
                    entity_type="web_app",
                    entity_id=coverage_gap.affected_entities[0]["entity_id"] if coverage_gap.affected_entities else "",
                    source_tool=self.name,
                    confidence=0.78,
                    evidence_ids=list(coverage_gap.evidence_ids),
                    source_execution_id=execution_id,
                    parser_version="active_validation_v1",
                )
            )

        for validation_result in result.validation_results:
            emit_entity_event(context, "validation_result", validation_result, source=self.name)
        for item in result.response_deltas:
            emit_entity_event(context, "response_delta", item, source=self.name)
        for item in result.proof_outcomes:
            emit_entity_event(context, "proof_outcome", item, source=self.name)
        for item in result.playbook_executions:
            emit_entity_event(context, "playbook_execution", item, source=self.name)
        for item in result.coverage_decisions:
            emit_entity_event(context, "coverage_decision", item, source=self.name)

        result.facts.update(
            {
                "active_validation.mode": mode,
                "active_validation.coverage_gaps": coverage_gaps,
                "active_validation.validation_counts": dict(validation_counts),
                "active_validation.enabled_families": enabled_families,
                "coverage_engine.mode": mode,
                "coverage_engine.coverage_gaps": coverage_gaps,
                "coverage_engine.validation_counts": dict(validation_counts),
                "coverage_engine.enabled_families": enabled_families,
            }
        )
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command=f"active validation mode={mode}",
                started_at=started_at,
                ended_at=now_utc(),
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=raw_artifact_paths,
            )
        )
        return result
