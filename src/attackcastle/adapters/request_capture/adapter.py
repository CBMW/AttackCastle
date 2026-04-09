from __future__ import annotations

import json
import re
from collections import defaultdict
from hashlib import sha1
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from attackcastle.adapters.base import build_tool_execution
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import (
    Endpoint,
    Evidence,
    Form,
    LoginSurface,
    Observation,
    Parameter,
    ReplayRequest,
    RunData,
    new_id,
    now_utc,
)
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event
from attackcastle.normalization.correlator import collect_web_targets

UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    rows: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        rows.append(item)
    return rows


def _infer_tags(url: str) -> list[str]:
    parsed = urlsplit(url)
    path = (parsed.path or "/").lower()
    tags: list[str] = []
    if "/api" in path or path.startswith("/v1") or path.startswith("/v2"):
        tags.append("api")
    if "graphql" in path:
        tags.extend(["api", "graphql"])
    if any(token in path for token in ("/admin", "/manage", "/wp-admin")):
        tags.append("admin")
    if any(token in path for token in ("/docs", "/swagger", "/openapi")):
        tags.extend(["docs", "api"])
    if path.endswith(".js"):
        tags.append("javascript")
    if path.endswith(".map"):
        tags.extend(["javascript", "source-map"])
    if any(path.endswith(suffix) for suffix in (".bak", ".old", ".zip", ".sql", ".env")):
        tags.append("backup")
    if parsed.query:
        tags.append("parameterized")
    return _unique(tags)


def _route_segments(url: str) -> list[str]:
    return [segment for segment in (urlsplit(url).path or "/").split("/") if segment]


def _segment_hint_type(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    if candidate.isdigit():
        return "numeric_id"
    if UUID_PATTERN.match(candidate):
        return "uuid"
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{4,}", candidate, re.IGNORECASE):
        return "slug"
    return ""


def _build_replay_context(url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    segments = _route_segments(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_values: dict[str, str] = {}
    object_hints: list[dict[str, Any]] = []
    for index, segment in enumerate(segments):
        hint_type = _segment_hint_type(segment)
        if not hint_type:
            continue
        object_hints.append(
            {
                "location": "path",
                "name": segments[index - 1] if index > 0 else "resource",
                "value": segment,
                "hint_type": hint_type,
            }
        )
    for name, value in query_pairs:
        query_values.setdefault(name, value)
        hint_type = _segment_hint_type(value)
        if not hint_type:
            continue
        object_hints.append(
            {
                "location": "query",
                "name": name,
                "value": value,
                "hint_type": hint_type,
            }
        )
    parent_path = "/".join(segments[:-1]) if len(segments) > 1 else ""
    path_pattern = []
    for segment in segments:
        hint_type = _segment_hint_type(segment)
        if hint_type == "numeric_id":
            path_pattern.append("{int}")
        elif hint_type == "uuid":
            path_pattern.append("{uuid}")
        elif hint_type == "slug":
            path_pattern.append("{slug}")
        else:
            path_pattern.append(segment.lower())
    return {
        "query_values": query_values,
        "route_segments": segments,
        "path_pattern": "/" + "/".join(path_pattern) if path_pattern else "/",
        "relationship_hints": {
            "parent_path": f"/{parent_path}" if parent_path else "/",
            "route_depth": len(segments),
            "looks_like_object_route": bool(object_hints),
        },
        "object_hints": object_hints,
    }


class RequestCaptureAdapter:
    name = "request_capture"
    capability = "request_capture"
    noise_score = 2
    cost_score = 2

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        return [f"capture canonical request GET {item['url']}" for item in collect_web_targets(run_data)[:20]]

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        execution_id = new_id("exec")
        result = AdapterResult()
        config = context.config.get("request_capture", {})
        max_saved_requests = int(config.get("max_saved_requests_per_webapp", 20))
        max_total_requests = int(config.get("max_total_requests", 800))
        user_agent = str(
            context.config.get("scan", {}).get(
                "user_agent",
                "AttackCastle/0.1 (+authorized-security-assessment)",
            )
        )
        replay_enabled = bool(context.config.get("active_validation", {}).get("request_replay_enabled", True))

        web_lookup = {item.webapp_id: item for item in run_data.web_apps}
        urls_by_webapp: dict[str, list[str]] = defaultdict(list)
        parameters_by_webapp: dict[str, list[str]] = defaultdict(list)
        login_reasons_by_webapp: dict[str, list[str]] = defaultdict(list)
        forms_by_webapp: dict[str, bool] = defaultdict(bool)

        for observation in run_data.observations:
            if observation.entity_type != "web_app":
                continue
            if observation.key in {
                "web.discovery.urls",
                "web.discovery.js_endpoints",
                "web.discovery.graphql_endpoints",
                "web.discovery.source_maps",
                "web.discovery.framework_artifacts",
            }:
                if isinstance(observation.value, list):
                    urls_by_webapp[observation.entity_id].extend(str(item) for item in observation.value)
            elif observation.key in {"web.input.parameters", "web.discovery.parameter_candidates"}:
                if isinstance(observation.value, list):
                    parameters_by_webapp[observation.entity_id].extend(str(item) for item in observation.value)
            elif observation.key == "web.login_portal":
                if isinstance(observation.value, list):
                    login_reasons_by_webapp[observation.entity_id].extend(str(item) for item in observation.value)
            elif observation.key == "web.forms.detected" and observation.value is True:
                forms_by_webapp[observation.entity_id] = True

        created_requests: list[dict[str, Any]] = []
        total_captured = 0

        for web_app in run_data.web_apps:
            candidate_urls = _unique([web_app.url, *urls_by_webapp.get(web_app.webapp_id, [])])
            if not candidate_urls:
                continue
            captured_for_webapp = 0
            parameter_names = _unique(parameters_by_webapp.get(web_app.webapp_id, []))
            for candidate_url in candidate_urls:
                if total_captured >= max_total_requests or captured_for_webapp >= max_saved_requests:
                    break
                tags = _infer_tags(candidate_url)
                parsed = urlsplit(candidate_url)
                query_names = [name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)]
                all_parameters = _unique([*parameter_names, *query_names])

                endpoint = Endpoint(
                    endpoint_id=new_id("endpoint"),
                    webapp_id=web_app.webapp_id,
                    asset_id=web_app.asset_id,
                    service_id=web_app.service_id,
                    url=candidate_url,
                    path=parsed.path or "/",
                    method="GET",
                    kind="replayable-endpoint",
                    tags=tags,
                    auth_hints=["unauthenticated-v1", *(_unique(login_reasons_by_webapp.get(web_app.webapp_id, []))[:3])],
                    confidence=0.82,
                    source_tool=self.name,
                    source_execution_id=execution_id,
                    parser_version="request_capture_v1",
                )
                result.endpoints.append(endpoint)
                emit_entity_event(context, "endpoint", endpoint, source=self.name)

                for parameter_name in all_parameters:
                    parameter = Parameter(
                        parameter_id=new_id("param"),
                        webapp_id=web_app.webapp_id,
                        name=parameter_name,
                        location="query",
                        endpoint_id=endpoint.endpoint_id,
                        confidence=0.74,
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="request_capture_v1",
                    )
                    result.parameters.append(parameter)
                    emit_entity_event(context, "parameter", parameter, source=self.name)

                if forms_by_webapp.get(web_app.webapp_id):
                    form = Form(
                        form_id=new_id("form"),
                        webapp_id=web_app.webapp_id,
                        action_url=candidate_url,
                        endpoint_id=endpoint.endpoint_id,
                        field_names=all_parameters or ["username", "password"],
                        has_password=any("pass" in item.lower() for item in all_parameters),
                        confidence=0.72,
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="request_capture_v1",
                    )
                    result.forms.append(form)
                    emit_entity_event(context, "form", form, source=self.name)

                if login_reasons_by_webapp.get(web_app.webapp_id):
                    login_surface = LoginSurface(
                        login_surface_id=new_id("login"),
                        webapp_id=web_app.webapp_id,
                        url=candidate_url,
                        endpoint_id=endpoint.endpoint_id,
                        reasons=_unique(login_reasons_by_webapp.get(web_app.webapp_id, [])),
                        username_fields=[item for item in all_parameters if item.lower() in {"user", "username", "email", "login"}]
                        or ["username"],
                        password_fields=[item for item in all_parameters if "pass" in item.lower()] or ["password"],
                        auth_hints=["interactive-login", "unauthenticated-v1"],
                        confidence=0.78,
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="request_capture_v1",
                    )
                    result.login_surfaces.append(login_surface)
                    emit_entity_event(context, "login_surface", login_surface, source=self.name)

                replay_request = ReplayRequest(
                    replay_request_id=new_id("replay"),
                    webapp_id=web_app.webapp_id,
                    asset_id=web_app.asset_id,
                    url=candidate_url,
                    method="GET",
                    endpoint_id=endpoint.endpoint_id,
                    service_id=web_app.service_id,
                    headers={"Accept": "*/*", "User-Agent": user_agent},
                    parameter_names=all_parameters,
                    body_field_names=[],
                    cookie_names=[],
                    tags=tags,
                    auth_hints=["unauthenticated-v1", *(_unique(login_reasons_by_webapp.get(web_app.webapp_id, []))[:3])],
                    context=_build_replay_context(candidate_url),
                    replay_enabled=replay_enabled,
                    confidence=0.85,
                    source_tool=self.name,
                    source_execution_id=execution_id,
                    parser_version="request_capture_v1",
                )
                result.replay_requests.append(replay_request)
                emit_entity_event(context, "replay_request", replay_request, source=self.name)

                created_requests.append(
                    {
                        "webapp_id": web_app.webapp_id,
                        "url": candidate_url,
                        "method": "GET",
                        "tags": tags,
                        "parameter_names": all_parameters,
                        "context": replay_request.context,
                    }
                )
                captured_for_webapp += 1
                total_captured += 1

            if captured_for_webapp:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.request_capture.count",
                        value=captured_for_webapp,
                        entity_type="web_app",
                        entity_id=web_app.webapp_id,
                        source_tool=self.name,
                        confidence=0.86,
                        source_execution_id=execution_id,
                        parser_version="request_capture_v1",
                    )
                )

        artifact_path = context.run_store.artifact_path(self.name, "captured_requests.json")
        artifact_path.write_text(json.dumps(created_requests, indent=2), encoding="utf-8")
        evidence = Evidence(
            evidence_id=new_id("evidence"),
            source_tool=self.name,
            kind="request_capture",
            snippet=f"captured {len(created_requests)} replayable request(s) across {len(run_data.web_apps)} web application(s)",
            artifact_path=str(artifact_path),
            selector={"kind": "active_validation", "family": "request_capture"},
            source_execution_id=execution_id,
            parser_version="request_capture_v1",
            confidence=0.9,
        )
        result.evidence.append(evidence)
        emit_entity_event(context, "evidence", evidence, source=self.name)
        emit_artifact_event(
            context,
            artifact_path=artifact_path,
            kind="request_capture",
            source_tool=self.name,
            caption="Replayable request inventory",
        )
        result.facts.update(
            {
                "request_capture.count": len(created_requests),
                "request_capture.replay_enabled": replay_enabled,
                "request_capture.captured_urls": [item["url"] for item in created_requests][:1000],
            }
        )
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="capture replayable web requests",
                started_at=started_at,
                ended_at=now_utc(),
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
                raw_artifact_paths=[str(artifact_path)],
            )
        )
        return result
