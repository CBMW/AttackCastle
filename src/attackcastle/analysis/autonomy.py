from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any
from urllib.parse import urljoin, urlsplit

from attackcastle.analysis.pentester_engine import (
    build_attack_paths as build_pentester_attack_paths,
    build_hypotheses as build_pentester_hypotheses,
    build_investigation_steps as build_pentester_investigation_steps,
    build_playbook_state as build_pentester_playbook_state,
    build_surface_signals as build_pentester_surface_signals,
)
from attackcastle.core.models import (
    ApprovalDecision,
    AttackPath,
    CoverageGap,
    CoverageDecision,
    Endpoint,
    Form,
    Hypothesis,
    InvestigationStep,
    LoginSurface,
    Parameter,
    PlaybookExecution,
    RunData,
    SurfaceSignal,
    ValidationTask,
    new_id,
    normalize_confidence,
    now_utc,
)

AUTO_APPROVAL_CLASSES = {"safe_auto"}
DISABLED_APPROVAL_CLASSES = {"disabled_bruteforce"}
MANUAL_APPROVAL_CLASSES = {
    "needs_approval_injection",
    "needs_approval_ssrf",
    "needs_approval_deserialization",
}
HYPOTHESIS_WEIGHTS = {
    "auth_surface": 72,
    "api_misconfiguration": 66,
    "injection": 84,
    "framework_cms_weakness": 70,
    "cloud_exposure": 78,
    "protocol_service_weakness": 64,
    "known_vuln_confirmation": 74,
    "exposure": 60,
}
SEVERITY_HINTS = {
    "auth_surface": "high",
    "api_misconfiguration": "medium",
    "injection": "critical",
    "framework_cms_weakness": "high",
    "cloud_exposure": "high",
    "protocol_service_weakness": "medium",
    "known_vuln_confirmation": "high",
    "exposure": "medium",
}
PLAYBOOK_WEIGHTS = {
    "object_access": 92,
    "input_reflection_injection": 90,
    "api_expansion": 84,
    "admin_debug_exposure": 80,
    "client_artifact_exposure": 76,
}
PLAYBOOK_LABELS = {
    "object_access": "Object Access Playbook",
    "input_reflection_injection": "Input Reflection And Injection Playbook",
    "api_expansion": "API Expansion Playbook",
    "admin_debug_exposure": "Admin And Debug Exposure Playbook",
    "client_artifact_exposure": "Client Artifact Exposure Playbook",
}


def _stable_id(prefix: str, key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]  # noqa: S324
    return f"{prefix}_{digest}"


def _task_state_lookup(run_data: RunData) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    for task in run_data.task_states:
        if not isinstance(task, dict):
            continue
        key = str(task.get("key") or "").strip()
        if key:
            lookup[key] = task
    return lookup


def _approval_config(config: dict[str, Any]) -> dict[str, Any]:
    approvals = config.get("approvals", {})
    return approvals if isinstance(approvals, dict) else {}


def approval_class_for_task(task_key: str | None, capability: str | None, config: dict[str, Any]) -> str:
    approvals = _approval_config(config)
    task_classes = approvals.get("task_classes", {})
    if isinstance(task_classes, dict) and task_key and task_key in task_classes:
        return str(task_classes[task_key])
    capability_classes = approvals.get("capability_classes", {})
    if isinstance(capability_classes, dict) and capability and capability in capability_classes:
        return str(capability_classes[capability])
    return str(approvals.get("default_class", "safe_auto"))


def approval_scope_key(task_key: str | None, approval_class: str, validation_task_id: str | None = None) -> str:
    if task_key:
        return f"task:{task_key}"
    if validation_task_id:
        return f"validation:{validation_task_id}"
    return f"class:{approval_class}"


def register_approval_decision(
    run_data: RunData,
    *,
    approval_class: str,
    status: str,
    reason: str,
    task_key: str | None = None,
    hypothesis_id: str | None = None,
    validation_task_id: str | None = None,
    decided_by: str = "operator",
) -> ApprovalDecision:
    scope_key = approval_scope_key(task_key, approval_class, validation_task_id)
    decision = ApprovalDecision(
        decision_id=new_id("approval"),
        approval_class=approval_class,
        status=status,
        scope_key=scope_key,
        task_key=task_key,
        hypothesis_id=hypothesis_id,
        validation_task_id=validation_task_id,
        decided_by=decided_by,
        reason=reason,
        created_at=now_utc(),
    )
    run_data.approval_decisions = [
        item for item in run_data.approval_decisions if item.scope_key != scope_key
    ]
    run_data.approval_decisions.append(decision)
    return decision


def _decision_lookup(run_data: RunData) -> dict[str, ApprovalDecision]:
    latest: dict[str, ApprovalDecision] = {}
    for decision in sorted(run_data.approval_decisions, key=lambda item: item.created_at):
        latest[decision.scope_key] = decision
    return latest


def _web_lookup(run_data: RunData) -> dict[str, Any]:
    return {item.webapp_id: item for item in run_data.web_apps}


def _service_lookup(run_data: RunData) -> dict[str, Any]:
    return {item.service_id: item for item in run_data.services}


def _entity_findings(run_data: RunData) -> dict[tuple[str, str], list[Any]]:
    lookup: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for finding in run_data.findings:
        if finding.suppressed:
            continue
        for entity in finding.affected_entities:
            lookup[(str(entity.get("entity_type")), str(entity.get("entity_id")))].append(finding)
    return lookup


def _observations_by_entity(run_data: RunData) -> dict[tuple[str, str], list[Any]]:
    lookup: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for observation in run_data.observations:
        lookup[(observation.entity_type, observation.entity_id)].append(observation)
    return lookup


def _coerce_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _guess_path(url: str) -> str:
    path = urlsplit(url).path or "/"
    return path if path.startswith("/") else f"/{path}"


def _absolute_url(base_url: str, value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return base_url
    if candidate.startswith(("http://", "https://")):
        return candidate
    return urljoin(base_url, candidate)


def _upsert_endpoint(
    rows: dict[str, Endpoint],
    *,
    webapp_id: str,
    asset_id: str,
    service_id: str | None,
    url: str,
    kind: str,
    tags: list[str] | None = None,
    auth_hints: list[str] | None = None,
    confidence: float = 0.7,
    source_tool: str = "internal",
) -> Endpoint:
    canonical_key = f"{webapp_id}|{url}|{kind}"
    endpoint_id = _stable_id("endpoint", canonical_key)
    if endpoint_id in rows:
        endpoint = rows[endpoint_id]
        endpoint.tags = sorted(set([*endpoint.tags, *(tags or [])]))
        endpoint.auth_hints = sorted(set([*endpoint.auth_hints, *(auth_hints or [])]))
        endpoint.confidence = max(endpoint.confidence, normalize_confidence(confidence, default=0.7))
        return endpoint
    endpoint = Endpoint(
        endpoint_id=endpoint_id,
        webapp_id=webapp_id,
        asset_id=asset_id,
        service_id=service_id,
        url=url,
        path=_guess_path(url),
        kind=kind,
        tags=sorted(set(tags or [])),
        auth_hints=sorted(set(auth_hints or [])),
        confidence=normalize_confidence(confidence, default=0.7),
        source_tool=source_tool,
        parser_version="autonomy_v2",
        canonical_key=canonical_key,
    )
    rows[endpoint_id] = endpoint
    return endpoint


def _upsert_parameter(
    rows: dict[str, Parameter],
    *,
    webapp_id: str,
    name: str,
    location: str,
    endpoint_id: str | None = None,
    confidence: float = 0.6,
    source_tool: str = "internal",
) -> Parameter:
    canonical_key = f"{webapp_id}|{endpoint_id or '-'}|{location}|{name.lower()}"
    parameter_id = _stable_id("param", canonical_key)
    if parameter_id in rows:
        parameter = rows[parameter_id]
        parameter.confidence = max(parameter.confidence, normalize_confidence(confidence, default=0.6))
        return parameter
    parameter = Parameter(
        parameter_id=parameter_id,
        webapp_id=webapp_id,
        endpoint_id=endpoint_id,
        name=name,
        location=location,
        confidence=normalize_confidence(confidence, default=0.6),
        source_tool=source_tool,
        parser_version="autonomy_v2",
        canonical_key=canonical_key,
        sensitive=name.lower() in {"token", "code", "password", "key", "secret"},
    )
    rows[parameter_id] = parameter
    return parameter


def _upsert_form(
    rows: dict[str, Form],
    *,
    webapp_id: str,
    action_url: str,
    field_names: list[str],
    has_password: bool,
    endpoint_id: str | None = None,
    confidence: float = 0.7,
    source_tool: str = "internal",
) -> Form:
    canonical_key = f"{webapp_id}|{action_url}|{','.join(sorted(field_names))}"
    form_id = _stable_id("form", canonical_key)
    if form_id in rows:
        form = rows[form_id]
        form.field_names = sorted(set([*form.field_names, *field_names]))
        form.has_password = form.has_password or has_password
        form.confidence = max(form.confidence, normalize_confidence(confidence, default=0.7))
        return form
    form = Form(
        form_id=form_id,
        webapp_id=webapp_id,
        action_url=action_url,
        endpoint_id=endpoint_id,
        method="POST" if has_password else "GET",
        field_names=sorted(set(field_names)),
        has_password=has_password,
        confidence=normalize_confidence(confidence, default=0.7),
        source_tool=source_tool,
        parser_version="autonomy_v2",
        canonical_key=canonical_key,
    )
    rows[form_id] = form
    return form


def _upsert_login_surface(
    rows: dict[str, LoginSurface],
    *,
    webapp_id: str,
    url: str,
    reasons: list[str],
    username_fields: list[str],
    password_fields: list[str],
    endpoint_id: str | None = None,
    confidence: float = 0.75,
    source_tool: str = "internal",
) -> LoginSurface:
    canonical_key = f"{webapp_id}|{url}"
    login_surface_id = _stable_id("login", canonical_key)
    if login_surface_id in rows:
        login_surface = rows[login_surface_id]
        login_surface.reasons = sorted(set([*login_surface.reasons, *reasons]))
        login_surface.username_fields = sorted(set([*login_surface.username_fields, *username_fields]))
        login_surface.password_fields = sorted(set([*login_surface.password_fields, *password_fields]))
        login_surface.confidence = max(
            login_surface.confidence,
            normalize_confidence(confidence, default=0.75),
        )
        return login_surface
    login_surface = LoginSurface(
        login_surface_id=login_surface_id,
        webapp_id=webapp_id,
        endpoint_id=endpoint_id,
        url=url,
        reasons=sorted(set(reasons)),
        username_fields=sorted(set(username_fields)),
        password_fields=sorted(set(password_fields)),
        auth_hints=["interactive-login"],
        confidence=normalize_confidence(confidence, default=0.75),
        source_tool=source_tool,
        parser_version="autonomy_v2",
        canonical_key=canonical_key,
    )
    rows[login_surface_id] = login_surface
    return login_surface


def _build_surface_entities(
    run_data: RunData,
) -> tuple[list[Endpoint], list[Parameter], list[Form], list[LoginSurface], list[CoverageGap]]:
    observations_by_entity = _observations_by_entity(run_data)
    endpoints: dict[str, Endpoint] = {}
    parameters: dict[str, Parameter] = {}
    forms: dict[str, Form] = {}
    login_surfaces: dict[str, LoginSurface] = {}
    coverage_gaps: dict[str, CoverageGap] = {}

    for web in run_data.web_apps:
        base_endpoint = _upsert_endpoint(
            endpoints,
            webapp_id=web.webapp_id,
            asset_id=web.asset_id,
            service_id=web.service_id,
            url=web.url,
            kind="base",
            tags=["base", "webapp"],
            confidence=0.95,
            source_tool=web.source_tool,
        )
        input_parameters: set[str] = set()
        login_reasons: list[str] = []
        observations = observations_by_entity.get(("web_app", web.webapp_id), [])
        for observation in observations:
            if observation.key == "web.discovery.urls":
                for url_value in _coerce_list(observation.value):
                    url = _absolute_url(web.url, str(url_value))
                    _upsert_endpoint(
                        endpoints,
                        webapp_id=web.webapp_id,
                        asset_id=web.asset_id,
                        service_id=web.service_id,
                        url=url,
                        kind="endpoint",
                        tags=["discovered-url"],
                        confidence=0.82,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.discovery.js_endpoints":
                for url_value in _coerce_list(observation.value):
                    url = _absolute_url(web.url, str(url_value))
                    _upsert_endpoint(
                        endpoints,
                        webapp_id=web.webapp_id,
                        asset_id=web.asset_id,
                        service_id=web.service_id,
                        url=url,
                        kind="js-endpoint",
                        tags=["javascript", "api-candidate"],
                        confidence=0.84,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.discovery.graphql_endpoints":
                for url_value in _coerce_list(observation.value):
                    url = _absolute_url(web.url, str(url_value))
                    _upsert_endpoint(
                        endpoints,
                        webapp_id=web.webapp_id,
                        asset_id=web.asset_id,
                        service_id=web.service_id,
                        url=url,
                        kind="graphql",
                        tags=["graphql", "api"],
                        confidence=0.88,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.discovery.source_maps":
                for url_value in _coerce_list(observation.value):
                    url = _absolute_url(web.url, str(url_value))
                    _upsert_endpoint(
                        endpoints,
                        webapp_id=web.webapp_id,
                        asset_id=web.asset_id,
                        service_id=web.service_id,
                        url=url,
                        kind="source-map",
                        tags=["source-map", "javascript"],
                        confidence=0.83,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.public_files":
                for item in _coerce_list(observation.value):
                    if not isinstance(item, dict):
                        continue
                    url = _absolute_url(web.url, str(item.get("final_url") or item.get("path") or web.url))
                    _upsert_endpoint(
                        endpoints,
                        webapp_id=web.webapp_id,
                        asset_id=web.asset_id,
                        service_id=web.service_id,
                        url=url,
                        kind="file",
                        tags=["public-file", str(item.get("classification") or "exposed")],
                        confidence=0.86,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.input.parameters":
                for name in _coerce_list(observation.value):
                    if not str(name).strip():
                        continue
                    input_parameters.add(str(name))
                    _upsert_parameter(
                        parameters,
                        webapp_id=web.webapp_id,
                        name=str(name),
                        location="input",
                        endpoint_id=base_endpoint.endpoint_id,
                        confidence=0.78,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.discovery.parameter_candidates":
                for name in _coerce_list(observation.value):
                    if not str(name).strip():
                        continue
                    _upsert_parameter(
                        parameters,
                        webapp_id=web.webapp_id,
                        name=str(name),
                        location="query",
                        endpoint_id=base_endpoint.endpoint_id,
                        confidence=0.73,
                        source_tool=observation.source_tool,
                    )
            elif observation.key == "web.forms.detected" and observation.value is True:
                field_names = sorted(input_parameters) or ["username", "password"]
                has_password = any("pass" in item.lower() for item in field_names)
                _upsert_form(
                    forms,
                    webapp_id=web.webapp_id,
                    action_url=web.url,
                    endpoint_id=base_endpoint.endpoint_id,
                    field_names=field_names,
                    has_password=has_password,
                    confidence=0.8,
                    source_tool=observation.source_tool,
                )
            elif observation.key == "web.login_portal":
                login_reasons.extend([str(item) for item in _coerce_list(observation.value) if str(item).strip()])
            elif observation.key == "coverage.gap" and isinstance(observation.value, dict):
                gap_value = observation.value
                gap_title = str(gap_value.get("reason") or "Coverage gap")
                gap_key = f"{web.webapp_id}|{gap_title}|{gap_value.get('url') or web.url}"
                coverage_gaps[_stable_id("gap", gap_key)] = CoverageGap(
                    coverage_gap_id=_stable_id("gap", gap_key),
                    title=gap_title,
                    source=f"observation:{observation.key}",
                    reason=str(gap_value.get("reason") or ""),
                    impact=str(gap_value.get("impact") or ""),
                    suggested_action=str(gap_value.get("suggested_action") or ""),
                    url=str(gap_value.get("url") or web.url),
                    affected_entities=[{"entity_type": "web_app", "entity_id": web.webapp_id}],
                    evidence_ids=list(observation.evidence_ids),
                    source_tool=observation.source_tool,
                )

        if web.forms_count > 0 and not any(item.webapp_id == web.webapp_id for item in forms.values()):
            _upsert_form(
                forms,
                webapp_id=web.webapp_id,
                action_url=web.url,
                endpoint_id=base_endpoint.endpoint_id,
                field_names=sorted(input_parameters) or ["username", "password"],
                has_password=bool(login_reasons),
                confidence=0.7,
                source_tool=web.source_tool,
            )
        if login_reasons:
            username_fields = sorted(
                [item for item in input_parameters if item.lower() in {"user", "username", "email", "login"}]
            ) or ["username"]
            password_fields = sorted([item for item in input_parameters if "pass" in item.lower()]) or ["password"]
            _upsert_login_surface(
                login_surfaces,
                webapp_id=web.webapp_id,
                endpoint_id=base_endpoint.endpoint_id,
                url=web.url,
                reasons=login_reasons,
                username_fields=username_fields,
                password_fields=password_fields,
                confidence=0.84,
                source_tool=web.source_tool,
            )

    return (
        sorted(endpoints.values(), key=lambda item: (item.webapp_id, item.kind, item.url)),
        sorted(parameters.values(), key=lambda item: (item.webapp_id, item.location, item.name)),
        sorted(forms.values(), key=lambda item: (item.webapp_id, item.action_url)),
        sorted(login_surfaces.values(), key=lambda item: (item.webapp_id, item.url)),
        sorted(coverage_gaps.values(), key=lambda item: (item.title, item.url or "")),
    )


def _default_approvals(run_data: RunData, config: dict[str, Any]) -> list[ApprovalDecision]:
    decisions = list(run_data.approval_decisions)
    lookup = _decision_lookup(run_data)
    approvals = _approval_config(config)
    auto_classes = {str(item) for item in approvals.get("auto_approve_classes", []) if str(item).strip()}
    auto_classes.update(AUTO_APPROVAL_CLASSES)
    for validation_task in run_data.validation_tasks:
        if validation_task.approval_class not in auto_classes:
            continue
        scope_key = approval_scope_key(
            validation_task.task_key,
            validation_task.approval_class,
            validation_task.validation_task_id,
        )
        if scope_key in lookup:
            continue
        decisions.append(
            ApprovalDecision(
                decision_id=_stable_id("approval", f"auto|{scope_key}"),
                approval_class=validation_task.approval_class,
                status="approved",
                scope_key=scope_key,
                task_key=validation_task.task_key,
                hypothesis_id=validation_task.hypothesis_id,
                validation_task_id=validation_task.validation_task_id,
                decided_by="system",
                reason="auto-approved by policy",
            )
        )
    return sorted(decisions, key=lambda item: item.created_at)


def _signal_hypotheses(run_data: RunData, config: dict[str, Any]) -> list[Hypothesis]:
    observations_by_entity = _observations_by_entity(run_data)
    findings_by_entity = _entity_findings(run_data)
    hypotheses: dict[str, Hypothesis] = {}

    def upsert_hypothesis(
        *,
        title: str,
        exploit_class: str,
        entity_type: str,
        entity_id: str,
        confidence: float,
        reasoning: str,
        evidence_ids: list[str],
        source_observation_ids: list[str],
        next_step: str,
        approval_class: str,
        validation_capability: str | None = None,
        task_key: str | None = None,
        tags: list[str] | None = None,
    ) -> None:
        affected_entities = [{"entity_type": entity_type, "entity_id": entity_id}]
        canonical_key = f"{exploit_class}|{entity_type}|{entity_id}|{title.lower()}"
        hypothesis_id = _stable_id("hyp", canonical_key)
        priority_score = HYPOTHESIS_WEIGHTS.get(exploit_class, 50)
        existing = hypotheses.get(hypothesis_id)
        if existing is not None:
            existing.confidence = max(existing.confidence, normalize_confidence(confidence, default=0.7))
            existing.priority_score = max(existing.priority_score, priority_score)
            existing.evidence_ids = sorted(set([*existing.evidence_ids, *evidence_ids]))
            existing.source_observation_ids = sorted(
                set([*existing.source_observation_ids, *source_observation_ids])
            )
            existing.tags = sorted(set([*existing.tags, *(tags or [])]))
            return
        hypotheses[hypothesis_id] = Hypothesis(
            hypothesis_id=hypothesis_id,
            title=title,
            exploit_class=exploit_class,
            confidence=normalize_confidence(confidence, default=0.7),
            priority_score=priority_score,
            severity_hint=SEVERITY_HINTS.get(exploit_class, "info"),
            approval_class=approval_class,
            playbook=exploit_class,
            reasoning=reasoning,
            next_validation_step=next_step,
            validation_capability=validation_capability,
            task_key=task_key,
            affected_entities=affected_entities,
            evidence_ids=sorted(set(evidence_ids)),
            required_preconditions=["externally reachable surface"],
            stop_conditions=["finding confirmed", "hypothesis rejected", "coverage exhausted"],
            evidence_goals=["capture proof", "classify exploitability", "record reproduction hints"],
            tags=sorted(set(tags or [exploit_class])),
            source_observation_ids=sorted(set(source_observation_ids)),
        )

    for entity_key, observations in observations_by_entity.items():
        entity_type, entity_id = entity_key
        for observation in observations:
            key = observation.key
            evidence_ids = list(observation.evidence_ids)
            observation_ids = [observation.observation_id]
            if key in {"web.admin_interface", "web.login_portal"}:
                upsert_hypothesis(
                    title="Internet-facing authentication surface requires validation",
                    exploit_class="auth_surface",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.83,
                    reasoning="Exposed login or admin behavior was detected and should be checked for hardening weaknesses.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Review lockout, MFA, password reset, and administrative path exposure.",
                    approval_class="safe_auto",
                    tags=["auth", "login", "exposure"],
                )
            elif key in {"web.api.docs.exposed", "web.discovery.graphql_endpoints"}:
                upsert_hypothesis(
                    title="Unauthenticated API surface likely exposes useful metadata",
                    exploit_class="api_misconfiguration",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.8,
                    reasoning="API docs or GraphQL routes often enable rapid endpoint expansion and unauthenticated enumeration.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Inspect API schemas, unauthenticated routes, and overexposed metadata.",
                    approval_class="safe_auto",
                    tags=["api", "graphql", "docs"],
                )
            elif key in {"web.discovery.parameter_candidates", "web.input.parameters", "web.sqlmap.candidate_score"}:
                upsert_hypothesis(
                    title="Parameter-rich surface should be tested for injection",
                    exploit_class="injection",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.76 if key != "web.sqlmap.candidate_score" else 0.84,
                    reasoning="Discovered parameters and structured input increase the chance of injectable behavior on exposed endpoints.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Run controlled injection validation against the best-ranked candidate parameters.",
                    approval_class="needs_approval_injection",
                    validation_capability="web_injection_scan",
                    task_key="run-sqlmap",
                    tags=["injection", "parameters"],
                )
            elif key in {"web.cors.misconfigured", "web.http_methods.permissive", "web.graphql.introspection_enabled"}:
                upsert_hypothesis(
                    title="Active validation confirmed web/API misconfiguration",
                    exploit_class="api_misconfiguration",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.87,
                    reasoning="Replay validation produced a concrete server response that indicates misconfiguration on an exposed route.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Preserve proof, review impacted routes, and assess business impact before reporting.",
                    approval_class="safe_auto",
                    tags=["active-validation", "misconfiguration"],
                )
            elif key == "web.js.sensitive_strings":
                upsert_hypothesis(
                    title="Sensitive data exposure confirmed in client-side assets",
                    exploit_class="exposure",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.85,
                    reasoning="Client-side JavaScript exposed token- or secret-like material during replay validation.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Validate the exposed values, rotate them if active, and assess reachable downstream APIs.",
                    approval_class="safe_auto",
                    tags=["active-validation", "javascript", "secret"],
                )
            elif key == "web.idor.candidate":
                upsert_hypothesis(
                    title="Access-control boundary needs manual review",
                    exploit_class="api_misconfiguration",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.68,
                    reasoning="Neighbor-object replay succeeded and may indicate IDOR/BOLA behavior.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Compare baseline and mutated object access manually to determine whether authorization is missing.",
                    approval_class="safe_auto",
                    tags=["idor", "bola", "candidate"],
                )
            elif key in {"web.xss.reflected", "web.sqli.error_based"}:
                upsert_hypothesis(
                    title="Replay validation produced a concrete injection signal",
                    exploit_class="injection",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.9,
                    reasoning="A replay mutation produced a reflected or database-style response signal on this application.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Preserve the reproduction request and triage impact before moving to reporting or deeper confirmation.",
                    approval_class="safe_auto",
                    validation_capability="active_validation_core",
                    task_key="run-active-validation",
                    tags=["active-validation", "injection"],
                )
            elif key == "web.sqlmap.injectable" and observation.value is True:
                upsert_hypothesis(
                    title="Injection candidate has already been validated by sqlmap",
                    exploit_class="injection",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.92,
                    reasoning="sqlmap reported injectable behavior on this internet-facing application.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Review the injectable parameter, DBMS fingerprint, and business impact for reporting.",
                    approval_class="safe_auto",
                    validation_capability="web_injection_scan",
                    task_key="run-sqlmap",
                    tags=["injection", "confirmed-signal"],
                )
            elif key in {"framework.scan.issue_count", "tech.wordpress.detected"}:
                upsert_hypothesis(
                    title="Framework or CMS-specific validation path is justified",
                    exploit_class="framework_cms_weakness",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.79,
                    reasoning="Framework or CMS fingerprints were observed, enabling targeted validation with high signal.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Run targeted framework or CMS validation and triage version-specific weakness indicators.",
                    approval_class="safe_auto",
                    validation_capability="cms_framework_scan",
                    task_key="run-framework-checks",
                    tags=["framework", "cms"],
                )
            elif key in {"cloud.storage.public", "cloud.storage.object_listing"}:
                upsert_hypothesis(
                    title="Cloud-hosted surface may be unintentionally public",
                    exploit_class="cloud_exposure",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.86,
                    reasoning="Public cloud storage-like behavior was detected on an external asset.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Validate listing access, object exposure, and business relevance of the public cloud surface.",
                    approval_class="safe_auto",
                    tags=["cloud", "storage"],
                )
            elif key.startswith("service.") and key.endswith(".exposed") and observation.value is True:
                upsert_hypothesis(
                    title="Externally reachable service should be validated for hardening gaps",
                    exploit_class="protocol_service_weakness",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.78,
                    reasoning="A remotely reachable non-HTTP service or administrative protocol is exposed to the internet.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Confirm exposure intent, authentication posture, and any version-specific risk indicators.",
                    approval_class="safe_auto",
                    tags=["service", "exposure"],
                )
            elif key in {"vuln.cve.top_priority", "vuln.template.detected", "web.nuclei.issue_count"}:
                upsert_hypothesis(
                    title="Known-vulnerability signals justify confirmation workflow",
                    exploit_class="known_vuln_confirmation",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.81,
                    reasoning="Version, template, or prioritization signals indicate a plausible known-vulnerability path.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Correlate banner or fingerprint data with exploitability signals and confirm impact.",
                    approval_class="safe_auto",
                    tags=["cve", "nuclei", "known-vuln"],
                )
            elif key in {"web.public_files", "thirdparty.github.reference", "thirdparty.package.reference"}:
                upsert_hypothesis(
                    title="Exposure of public artifacts may enable further pivoting",
                    exploit_class="exposure",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    confidence=0.72,
                    reasoning="Public files or third-party references were exposed on an internet-facing application.",
                    evidence_ids=evidence_ids,
                    source_observation_ids=observation_ids,
                    next_step="Review exposed artifacts for sensitive metadata, hidden routes, and technology clues.",
                    approval_class="safe_auto",
                    tags=["exposure", "artifact"],
                )

        for finding in findings_by_entity.get(entity_key, []):
            exploit_class = "known_vuln_confirmation"
            if "sql" in finding.category.lower() or "inject" in finding.title.lower():
                exploit_class = "injection"
            elif "admin" in finding.title.lower() or "login" in finding.title.lower():
                exploit_class = "auth_surface"
            upsert_hypothesis(
                title=f"Finding-backed hypothesis: {finding.title}",
                exploit_class=exploit_class,
                entity_type=entity_type,
                entity_id=entity_id,
                confidence=0.95,
                reasoning="A correlated finding already supports this attack path.",
                evidence_ids=list(finding.evidence_ids),
                source_observation_ids=[],
                next_step="Preserve the reproduction trail and remediation guidance for reporting.",
                approval_class="safe_auto",
                tags=["finding-backed", finding.severity.value],
            )

    return list(hypotheses.values())


def _resolve_hypothesis_status(
    hypothesis: Hypothesis,
    *,
    decisions: dict[str, ApprovalDecision],
    task_states: dict[str, dict[str, Any]],
    run_data: RunData,
) -> str:
    attack_path = next(
        (item for item in run_data.attack_paths if item.attack_path_id == hypothesis.attack_path_id),
        None,
    )
    if attack_path is not None:
        if attack_path.proof_status == "confirmed":
            return "confirmed"
        if attack_path.status == "blocked":
            return "rejected"
        if attack_path.status == "manual_followup":
            return "approval_required"
        if attack_path.status == "insufficient_signal":
            return "rejected"
    if any(
        finding.status == "confirmed" and not finding.suppressed
        for finding in run_data.findings
        for entity in finding.affected_entities
        if entity in hypothesis.affected_entities
    ):
        return "confirmed"
    if hypothesis.task_key and hypothesis.task_key in task_states:
        task_status = str(task_states[hypothesis.task_key].get("status", "")).lower()
        if task_status == "running":
            return "validating"
        if task_status == "completed":
            return "ready_to_validate"
        if task_status in {"blocked", "skipped"}:
            return "rejected"
    scope_key = approval_scope_key(hypothesis.task_key, hypothesis.approval_class, None)
    decision = decisions.get(scope_key)
    if decision is not None:
        if decision.status == "rejected":
            return "rejected"
        if decision.status == "approved" and hypothesis.task_key:
            return "ready_to_validate"
    if hypothesis.approval_class in DISABLED_APPROVAL_CLASSES:
        return "rejected"
    if hypothesis.approval_class in MANUAL_APPROVAL_CLASSES:
        return "approval_required"
    return "ready_to_validate"


def _build_validation_tasks(run_data: RunData, hypotheses: list[Hypothesis], config: dict[str, Any]) -> list[ValidationTask]:
    decisions = _decision_lookup(run_data)
    task_states = _task_state_lookup(run_data)
    steps_by_path = {
        item.attack_path_id: item
        for item in run_data.investigation_steps
        if not bool(item.details.get("fallback"))
    }
    finding_lookup: dict[tuple[str, str], list[str]] = defaultdict(list)
    for finding in run_data.findings:
        for entity in finding.affected_entities:
            finding_lookup[(str(entity.get("entity_type")), str(entity.get("entity_id")))].append(finding.finding_id)

    tasks: list[ValidationTask] = []
    for hypothesis in hypotheses:
        related_finding_ids = [
            finding_id
            for entity in hypothesis.affected_entities
            for finding_id in finding_lookup.get((entity["entity_type"], entity["entity_id"]), [])
        ]
        scope_key = approval_scope_key(hypothesis.task_key, hypothesis.approval_class, None)
        decision = decisions.get(scope_key)
        task_status = _resolve_hypothesis_status(
            hypothesis,
            decisions=decisions,
            task_states=task_states,
            run_data=run_data,
        )
        primary_step = steps_by_path.get(hypothesis.attack_path_id or "")
        command_preview = [hypothesis.next_validation_step]
        if hypothesis.task_key == "run-sqlmap":
            targets = [
                web.url
                for web in run_data.web_apps
                if any(
                    entity.get("entity_type") == "web_app" and entity.get("entity_id") == web.webapp_id
                    for entity in hypothesis.affected_entities
                )
            ]
            command_preview = [f"sqlmap candidate -> {target}" for target in targets] or command_preview
        tasks.append(
            ValidationTask(
                validation_task_id=_stable_id("vtask", hypothesis.hypothesis_id),
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                exploit_class=hypothesis.exploit_class,
                status=task_status,
                approval_class=hypothesis.approval_class,
                rationale=hypothesis.reasoning,
                next_action=hypothesis.next_validation_step,
                validation_capability=hypothesis.validation_capability,
                task_key=hypothesis.task_key,
                attack_path_id=hypothesis.attack_path_id,
                playbook_key=hypothesis.playbook,
                step_key=hypothesis.step_key or (primary_step.step_key if primary_step else ""),
                auto_runnable=hypothesis.approval_class in AUTO_APPROVAL_CLASSES,
                command_preview=(
                    [primary_step.title, *command_preview]
                    if primary_step is not None and primary_step.title not in command_preview
                    else command_preview
                ),
                affected_entities=list(hypothesis.affected_entities),
                evidence_ids=list(hypothesis.evidence_ids),
                related_finding_ids=sorted(set(related_finding_ids)),
                blocking_reason=(
                    None
                    if task_status != "approval_required"
                    else (
                        decision.reason
                        if decision is not None
                        else (
                            primary_step.rationale
                            if primary_step is not None and primary_step.rationale
                            else f"approval required for {hypothesis.approval_class}"
                        )
                    )
                ),
                result=decision.status if decision is not None else None,
            )
        )
    return sorted(tasks, key=lambda item: (item.status != "approval_required", item.auto_runnable, item.title))


def _build_attack_paths(run_data: RunData, hypotheses: list[Hypothesis]) -> list[AttackPath]:
    by_asset: dict[str, list[Hypothesis]] = defaultdict(list)
    service_lookup = _service_lookup(run_data)
    web_lookup = _web_lookup(run_data)
    for hypothesis in hypotheses:
        for entity in hypothesis.affected_entities:
            entity_type = entity.get("entity_type")
            entity_id = entity.get("entity_id")
            asset_id = None
            if entity_type == "asset":
                asset_id = entity_id
            elif entity_type == "service" and entity_id in service_lookup:
                asset_id = service_lookup[entity_id].asset_id
            elif entity_type == "web_app" and entity_id in web_lookup:
                asset_id = web_lookup[entity_id].asset_id
            if asset_id:
                by_asset[str(asset_id)].append(hypothesis)
    attack_paths: list[AttackPath] = []
    for asset_id, rows in by_asset.items():
        if len(rows) < 2:
            continue
        rows = sorted(rows, key=lambda item: (-item.priority_score, -item.confidence, item.title))
        step_titles = [item.title for item in rows[:4]]
        evidence_ids = sorted({evidence_id for item in rows for evidence_id in item.evidence_ids})
        attack_paths.append(
            AttackPath(
                attack_path_id=_stable_id("path", f"{asset_id}|{'|'.join(step_titles)}"),
                title=f"Attack path on {asset_id}",
                summary=" -> ".join(step_titles[:3]),
                risk_score=min(100, int(sum(item.priority_score for item in rows[:3]) / max(1, len(rows[:3])))),
                affected_entities=[{"entity_type": "asset", "entity_id": asset_id}],
                step_titles=step_titles,
                hypothesis_ids=[item.hypothesis_id for item in rows[:4]],
                evidence_ids=evidence_ids[:12],
                tags=sorted({tag for item in rows[:4] for tag in item.tags}),
            )
        )
    return sorted(attack_paths, key=lambda item: (-item.risk_score, item.title))


def refresh_autonomy_state(run_data: RunData, config: dict[str, Any]) -> None:
    endpoints, parameters, forms, login_surfaces, coverage_gaps = _build_surface_entities(run_data)
    run_data.endpoints = endpoints
    run_data.parameters = parameters
    run_data.forms = forms
    run_data.login_surfaces = login_surfaces
    run_data.coverage_gaps = coverage_gaps

    run_data.surface_signals = build_pentester_surface_signals(run_data, config)
    run_data.attack_paths = build_pentester_attack_paths(run_data, run_data.surface_signals, config)
    run_data.investigation_steps = build_pentester_investigation_steps(
        run_data,
        run_data.attack_paths,
        run_data.surface_signals,
        config,
    )
    run_data.hypotheses = build_pentester_hypotheses(run_data.attack_paths, run_data.investigation_steps)
    run_data.playbook_executions, run_data.coverage_decisions = build_pentester_playbook_state(
        run_data.attack_paths,
        run_data.investigation_steps,
    )
    run_data.approval_decisions = _default_approvals(run_data, config)
    decisions = _decision_lookup(run_data)
    task_states = _task_state_lookup(run_data)
    for hypothesis in run_data.hypotheses:
        hypothesis.status = _resolve_hypothesis_status(
            hypothesis,
            decisions=decisions,
            task_states=task_states,
            run_data=run_data,
        )
    run_data.validation_tasks = _build_validation_tasks(run_data, run_data.hypotheses, config)
    for attack_path in run_data.attack_paths:
        attack_path.hypothesis_ids = [
            item.hypothesis_id for item in run_data.hypotheses if item.attack_path_id == attack_path.attack_path_id
        ]
        attack_path.validation_task_ids = [
            item.validation_task_id
            for item in run_data.validation_tasks
            if item.attack_path_id == attack_path.attack_path_id
        ]

    queue_summary = {
        "hypothesis_count": len(run_data.hypotheses),
        "validation_task_count": len(run_data.validation_tasks),
        "approval_required_count": len(
            [item for item in run_data.validation_tasks if item.status == "approval_required"]
        ),
        "confirmed_count": len([item for item in run_data.validation_tasks if item.status == "confirmed"]),
        "coverage_gap_count": len(run_data.coverage_gaps),
        "attack_path_count": len(run_data.attack_paths),
        "playbook_execution_count": len(run_data.playbook_executions),
    }
    attack_surface_summary = {
        "endpoint_count": len(run_data.endpoints),
        "parameter_count": len(run_data.parameters),
        "form_count": len(run_data.forms),
        "login_surface_count": len(run_data.login_surfaces),
        "surface_signal_count": len(run_data.surface_signals),
        "attack_path_count": len(run_data.attack_paths),
        "investigation_step_count": len(run_data.investigation_steps),
    }
    run_data.facts["autonomy.queue_summary"] = queue_summary
    run_data.facts["attack_surface.summary"] = attack_surface_summary
    run_data.facts["approval.pending_count"] = queue_summary["approval_required_count"]
