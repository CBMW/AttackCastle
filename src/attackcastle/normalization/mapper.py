from __future__ import annotations

import hashlib
from typing import Any

from attackcastle.core.interfaces import AdapterResult
from attackcastle.core.models import (
    Assertion,
    EvidenceArtifact,
    NormalizedEntity,
    RunData,
    TaskResult,
    new_id,
    normalize_confidence,
)
from attackcastle.normalization.dedupe import make_key
from attackcastle.scope.domains import registrable_domain


def _merge_facts(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in incoming.items():
        if key not in merged:
            merged[key] = value
            continue
        current = merged[key]
        if isinstance(current, list) and isinstance(value, list):
            for item in value:
                if item not in current:
                    current.append(item)
            merged[key] = current
        elif isinstance(current, bool) and isinstance(value, bool):
            merged[key] = current or value
        elif isinstance(current, (int, float)) and isinstance(value, (int, float)):
            merged[key] = max(current, value)
        else:
            merged[key] = value
    return merged


def _canonical_id(prefix: str, key: str) -> str:
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]  # noqa: S324
    return f"{prefix}_{digest}"


def _append_alias(run_data: RunData, canonical_id: str, previous_id: str) -> None:
    if canonical_id == previous_id:
        return
    alias_list = run_data.alias_map.setdefault(canonical_id, [])
    if previous_id not in alias_list:
        alias_list.append(previous_id)


def _create_assertions(run_data: RunData) -> None:
    # Lightweight correlated assertions to keep observation and assertion layers distinct.
    existing_keys = {(assertion.key, tuple(sorted((ref["entity_id"] for ref in assertion.entity_refs)))) for assertion in run_data.assertions}
    grouped: dict[tuple[str, str], list[str]] = {}
    for observation in run_data.observations:
        if observation.key.endswith(".detected") and observation.value is True:
            group_key = (observation.entity_type, observation.entity_id)
            grouped.setdefault(group_key, []).append(observation.observation_id)

    for (entity_type, entity_id), observation_ids in grouped.items():
        key = "entity.detected"
        composite = (key, (entity_id,))
        if composite in existing_keys:
            continue
        run_data.assertions.append(
            Assertion(
                assertion_id=new_id("assert"),
                key=key,
                value=True,
                confidence=0.8,
                entity_refs=[{"entity_type": entity_type, "entity_id": entity_id}],
                source_observation_ids=observation_ids,
            )
        )


def _normalized_entity(
    entity_type: str,
    attributes: dict[str, Any],
    *,
    evidence_ids: list[str] | None = None,
    source_tool: str = "internal",
    source_execution_id: str | None = None,
    parser_version: str | None = None,
) -> NormalizedEntity:
    parts = [entity_type]
    for key in sorted(attributes):
        value = attributes.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            parts.append(f"{key}={','.join(str(item) for item in value)}")
        else:
            parts.append(f"{key}={value}")
    canonical_key = make_key(*parts)
    return NormalizedEntity(
        entity_id=_canonical_id("entity", canonical_key),
        entity_type=entity_type,
        attributes=attributes,
        evidence_ids=list(evidence_ids or []),
        source_tool=source_tool,
        source_execution_id=source_execution_id,
        parser_version=parser_version,
        canonical_key=canonical_key,
    )


def _extend_unique(items: list[str], values: list[str]) -> None:
    for value in values:
        if value not in items:
            items.append(value)


def _merge_asset(existing, incoming) -> None:  # noqa: ANN001
    if not existing.ip and incoming.ip:
        existing.ip = incoming.ip
    if not existing.parent_asset_id and incoming.parent_asset_id:
        existing.parent_asset_id = incoming.parent_asset_id
    _extend_unique(existing.resolved_ips, list(getattr(incoming, "resolved_ips", [])))
    if incoming.ip and incoming.ip not in existing.resolved_ips:
        existing.resolved_ips.append(incoming.ip)
    _extend_unique(existing.aliases, list(getattr(incoming, "aliases", [])))
    if not existing.source_execution_id and incoming.source_execution_id:
        existing.source_execution_id = incoming.source_execution_id
    if not existing.parser_version and incoming.parser_version:
        existing.parser_version = incoming.parser_version
    if not existing.canonical_key and incoming.canonical_key:
        existing.canonical_key = incoming.canonical_key


def _merge_normalized_entity(existing: NormalizedEntity, incoming: NormalizedEntity) -> None:
    for key, value in incoming.attributes.items():
        if key not in existing.attributes or existing.attributes[key] in (None, "", [], {}):
            existing.attributes[key] = value
            continue
        current = existing.attributes[key]
        if isinstance(current, list) and isinstance(value, list):
            for item in value:
                if item not in current:
                    current.append(item)
            existing.attributes[key] = current
        elif isinstance(current, dict) and isinstance(value, dict):
            merged = dict(current)
            merged.update(value)
            existing.attributes[key] = merged
    _extend_unique(existing.evidence_ids, incoming.evidence_ids)
    if not existing.source_task_id and incoming.source_task_id:
        existing.source_task_id = incoming.source_task_id
    if not existing.source_execution_id and incoming.source_execution_id:
        existing.source_execution_id = incoming.source_execution_id
    if not existing.parser_version and incoming.parser_version:
        existing.parser_version = incoming.parser_version


def _register_normalized_entities(run_data: RunData, entities: list[NormalizedEntity]) -> None:
    existing_keys = {
        item.canonical_key or make_key(item.entity_type, item.attributes): item for item in run_data.normalized_entities
    }
    for entity in entities:
        entity.canonical_key = entity.canonical_key or make_key(entity.entity_type, entity.attributes)
        existing = existing_keys.get(entity.canonical_key)
        if existing is not None:
            _merge_normalized_entity(existing, entity)
            _append_alias(run_data, existing.entity_id, entity.entity_id)
            continue
        old_id = entity.entity_id
        entity.entity_id = _canonical_id("entity", entity.canonical_key)
        run_data.normalized_entities.append(entity)
        existing_keys[entity.canonical_key] = entity
        _append_alias(run_data, entity.entity_id, old_id)


def _register_evidence_artifacts(run_data: RunData, artifacts: list[EvidenceArtifact]) -> None:
    existing_keys = {
        make_key(item.kind, item.path, item.source_tool, item.source_task_id, item.source_execution_id): item
        for item in run_data.evidence_artifacts
    }
    for artifact in artifacts:
        key = make_key(
            artifact.kind,
            artifact.path,
            artifact.source_tool,
            artifact.source_task_id,
            artifact.source_execution_id,
        )
        existing = existing_keys.get(key)
        if existing is not None:
            if not existing.hash_sha256 and artifact.hash_sha256:
                existing.hash_sha256 = artifact.hash_sha256
            if not existing.caption and artifact.caption:
                existing.caption = artifact.caption
            if not existing.source_task_id and artifact.source_task_id:
                existing.source_task_id = artifact.source_task_id
            if artifact.metadata:
                existing.metadata.update(artifact.metadata)
            _append_alias(run_data, existing.artifact_id, artifact.artifact_id)
            continue
        old_id = artifact.artifact_id
        artifact.artifact_id = _canonical_id("artifact", key)
        run_data.evidence_artifacts.append(artifact)
        existing_keys[key] = artifact
        _append_alias(run_data, artifact.artifact_id, old_id)


def _register_task_results(run_data: RunData, task_results: list[TaskResult]) -> None:
    existing_by_id = {item.task_id: item for item in run_data.task_results}
    for task_result in task_results:
        existing = existing_by_id.get(task_result.task_id)
        if existing is None:
            run_data.task_results.append(task_result)
            existing_by_id[task_result.task_id] = task_result
            continue
        existing.status = task_result.status or existing.status
        existing.command = task_result.command or existing.command
        existing.exit_code = task_result.exit_code
        existing.started_at = task_result.started_at
        existing.finished_at = task_result.finished_at
        existing.raw_artifacts = list(task_result.raw_artifacts)
        existing.parsed_entities = list(task_result.parsed_entities)
        existing.metrics = dict(task_result.metrics)
        existing.warnings = list(task_result.warnings)


def _legacy_entities_to_normalized(result: AdapterResult) -> list[NormalizedEntity]:
    normalized: list[NormalizedEntity] = []
    for asset in result.assets:
        if asset.kind == "domain":
            normalized.append(
                _normalized_entity(
                    "Hostname" if "." in asset.name else "Domain",
                    {
                        "fqdn": asset.name if "." in asset.name else None,
                        "value": asset.name,
                        "root_domain": registrable_domain(asset.name) or asset.name,
                        "source": asset.source_tool,
                    },
                    source_tool=asset.source_tool,
                    source_execution_id=asset.source_execution_id,
                    parser_version=asset.parser_version,
                )
            )
        elif asset.ip:
            normalized.append(
                _normalized_entity(
                    "IPAddress",
                    {
                        "address": asset.ip,
                        "version": 6 if ":" in asset.ip else 4,
                        "source": asset.source_tool,
                    },
                    source_tool=asset.source_tool,
                    source_execution_id=asset.source_execution_id,
                    parser_version=asset.parser_version,
                )
            )
        else:
            normalized.append(
                _normalized_entity(
                    "Hostname",
                    {
                        "fqdn": asset.name,
                        "root_domain": registrable_domain(asset.name) or asset.name,
                        "source": asset.source_tool,
                    },
                    source_tool=asset.source_tool,
                    source_execution_id=asset.source_execution_id,
                    parser_version=asset.parser_version,
                )
            )
    for service in result.services:
        normalized.append(
            _normalized_entity(
                "PortService",
                {
                    "asset_id": service.asset_id,
                    "port": service.port,
                    "protocol": service.protocol,
                    "state": service.state,
                    "service_name": service.name,
                    "banner": service.banner,
                    "confidence": 1.0,
                },
                source_tool=service.source_tool,
                source_execution_id=service.source_execution_id,
                parser_version=service.parser_version,
            )
        )
    for web_app in result.web_apps:
        normalized.append(
            _normalized_entity(
                "WebService",
                {
                    "asset_id": web_app.asset_id,
                    "service_id": web_app.service_id,
                    "url": web_app.url,
                    "title": web_app.title,
                    "status_code": web_app.status_code,
                },
                source_tool=web_app.source_tool,
                source_execution_id=web_app.source_execution_id,
                parser_version=web_app.parser_version,
            )
        )
    for tls_item in result.tls_assets:
        normalized.append(
            _normalized_entity(
                "Certificate",
                {
                    "asset_id": tls_item.asset_id,
                    "service_id": tls_item.service_id,
                    "host": tls_item.host,
                    "port": tls_item.port,
                    "subject": tls_item.subject,
                    "issuer": tls_item.issuer,
                    "not_before": tls_item.not_before,
                    "not_after": tls_item.not_after,
                    "sans": list(tls_item.sans),
                },
                source_tool=tls_item.source_tool,
                source_execution_id=tls_item.source_execution_id,
                parser_version=tls_item.parser_version,
            )
        )
    for endpoint in result.endpoints:
        normalized.append(
            _normalized_entity(
                "WebEndpoint",
                {
                    "asset_id": endpoint.asset_id,
                    "service_id": endpoint.service_id,
                    "webapp_id": endpoint.webapp_id,
                    "base_url": endpoint.url.rsplit(endpoint.path, 1)[0] if endpoint.path and endpoint.url.endswith(endpoint.path) else endpoint.url,
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "status_code": None,
                    "source": endpoint.source_tool,
                },
                source_tool=endpoint.source_tool,
                source_execution_id=endpoint.source_execution_id,
                parser_version=endpoint.parser_version,
            )
        )
    for replay_request in result.replay_requests:
        normalized.append(
            _normalized_entity(
                "ReplayableRequest",
                {
                    "asset_id": replay_request.asset_id,
                    "service_id": replay_request.service_id,
                    "webapp_id": replay_request.webapp_id,
                    "url": replay_request.url,
                    "method": replay_request.method,
                    "headers": dict(replay_request.headers),
                    "body": replay_request.context.get("body"),
                    "cookies": list(replay_request.cookie_names),
                    "source": replay_request.source_tool,
                },
                source_tool=replay_request.source_tool,
                source_execution_id=replay_request.source_execution_id,
                parser_version=replay_request.parser_version,
            )
        )
    return normalized


def merge_adapter_result(run_data: RunData, result: AdapterResult) -> None:
    asset_map: dict[str, str] = {}
    service_map: dict[str, str] = {}
    web_map: dict[str, str] = {}
    tls_map: dict[str, str] = {}
    endpoint_map: dict[str, str] = {}
    replay_request_map: dict[str, str] = {}
    evidence_map: dict[str, str] = {}

    existing_asset_keys = {
        make_key(asset.kind, asset.name, asset.ip, asset.parent_asset_id): asset.asset_id
        for asset in run_data.assets
    }
    existing_assets_by_id = {asset.asset_id: asset for asset in run_data.assets}
    for asset in result.assets:
        existing_by_id = existing_assets_by_id.get(asset.asset_id)
        if existing_by_id is not None:
            _merge_asset(existing_by_id, asset)
            asset_map[asset.asset_id] = existing_by_id.asset_id
            continue
        key = make_key(asset.kind, asset.name, asset.ip, asset.parent_asset_id)
        canonical_id = _canonical_id("asset", key)
        asset.canonical_key = key
        if key in existing_asset_keys:
            existing_id = existing_asset_keys[key]
            asset_map[asset.asset_id] = existing_id
            _append_alias(run_data, existing_id, asset.asset_id)
            continue
        old_id = asset.asset_id
        asset.asset_id = canonical_id
        run_data.assets.append(asset)
        existing_asset_keys[key] = asset.asset_id
        existing_assets_by_id[asset.asset_id] = asset
        asset_map[old_id] = asset.asset_id
        _append_alias(run_data, asset.asset_id, old_id)

    existing_service_keys = {
        make_key(s.asset_id, s.port, s.protocol, s.state, s.name): s.service_id
        for s in run_data.services
    }
    for service in result.services:
        service.asset_id = asset_map.get(service.asset_id, service.asset_id)
        key = make_key(service.asset_id, service.port, service.protocol, service.state, service.name)
        canonical_id = _canonical_id("service", key)
        service.canonical_key = key
        if key in existing_service_keys:
            existing_id = existing_service_keys[key]
            service_map[service.service_id] = existing_id
            _append_alias(run_data, existing_id, service.service_id)
            continue
        old_id = service.service_id
        service.service_id = canonical_id
        run_data.services.append(service)
        existing_service_keys[key] = service.service_id
        service_map[old_id] = service.service_id
        _append_alias(run_data, service.service_id, old_id)

    existing_web_keys = {
        make_key(w.asset_id, w.service_id, w.url): w.webapp_id for w in run_data.web_apps
    }
    for web_app in result.web_apps:
        web_app.asset_id = asset_map.get(web_app.asset_id, web_app.asset_id)
        web_app.service_id = (
            service_map.get(web_app.service_id, web_app.service_id) if web_app.service_id else None
        )
        key = make_key(web_app.asset_id, web_app.service_id, web_app.url)
        canonical_id = _canonical_id("web", key)
        web_app.canonical_key = key
        if key in existing_web_keys:
            existing_id = existing_web_keys[key]
            web_map[web_app.webapp_id] = existing_id
            _append_alias(run_data, existing_id, web_app.webapp_id)
            continue
        old_id = web_app.webapp_id
        web_app.webapp_id = canonical_id
        run_data.web_apps.append(web_app)
        existing_web_keys[key] = web_app.webapp_id
        web_map[old_id] = web_app.webapp_id
        _append_alias(run_data, web_app.webapp_id, old_id)

    existing_tls_keys = {
        make_key(t.asset_id, t.host, t.port, t.protocol): t.tls_id for t in run_data.tls_assets
    }
    for tls_item in result.tls_assets:
        tls_item.asset_id = asset_map.get(tls_item.asset_id, tls_item.asset_id)
        tls_item.service_id = (
            service_map.get(tls_item.service_id, tls_item.service_id) if tls_item.service_id else None
        )
        key = make_key(tls_item.asset_id, tls_item.host, tls_item.port, tls_item.protocol)
        canonical_id = _canonical_id("tls", key)
        tls_item.canonical_key = key
        if key in existing_tls_keys:
            existing_id = existing_tls_keys[key]
            tls_map[tls_item.tls_id] = existing_id
            _append_alias(run_data, existing_id, tls_item.tls_id)
            continue
        old_id = tls_item.tls_id
        tls_item.tls_id = canonical_id
        run_data.tls_assets.append(tls_item)
        existing_tls_keys[key] = tls_item.tls_id
        tls_map[old_id] = tls_item.tls_id
        _append_alias(run_data, tls_item.tls_id, old_id)

    existing_tech_keys = {
        make_key(t.asset_id, t.webapp_id, t.name, t.version): t.tech_id for t in run_data.technologies
    }
    for tech in result.technologies:
        tech.asset_id = asset_map.get(tech.asset_id, tech.asset_id)
        tech.webapp_id = web_map.get(tech.webapp_id, tech.webapp_id) if tech.webapp_id else None
        tech.confidence = normalize_confidence(tech.confidence, default=0.5)
        key = make_key(tech.asset_id, tech.webapp_id, tech.name, tech.version)
        canonical_id = _canonical_id("tech", key)
        tech.canonical_key = key
        if key in existing_tech_keys:
            existing_id = existing_tech_keys[key]
            _append_alias(run_data, existing_id, tech.tech_id)
            continue
        old_id = tech.tech_id
        tech.tech_id = canonical_id
        run_data.technologies.append(tech)
        existing_tech_keys[key] = tech.tech_id
        _append_alias(run_data, tech.tech_id, old_id)

    existing_evidence_keys = {
        make_key(e.source_tool, e.kind, e.snippet, e.artifact_path, e.selector): e.evidence_id
        for e in run_data.evidence
    }
    for evidence in result.evidence:
        snippet_key = make_key(evidence.source_tool, evidence.kind, evidence.snippet, evidence.artifact_path, evidence.selector)
        canonical_id = _canonical_id("evidence", snippet_key)
        evidence.evidence_hash = hashlib.sha256(snippet_key.encode("utf-8")).hexdigest()
        if snippet_key in existing_evidence_keys:
            existing_id = existing_evidence_keys[snippet_key]
            evidence_map[evidence.evidence_id] = existing_id
            _append_alias(run_data, existing_id, evidence.evidence_id)
            continue
        old_id = evidence.evidence_id
        evidence.evidence_id = canonical_id
        run_data.evidence.append(evidence)
        existing_evidence_keys[snippet_key] = evidence.evidence_id
        evidence_map[old_id] = evidence.evidence_id
        _append_alias(run_data, evidence.evidence_id, old_id)

    existing_obs_keys = {
        make_key(obs.entity_type, obs.entity_id, obs.key, obs.value): obs.observation_id
        for obs in run_data.observations
    }
    for observation in result.observations:
        observation.confidence = normalize_confidence(observation.confidence, default=1.0)
        if observation.entity_type == "asset":
            observation.entity_id = asset_map.get(observation.entity_id, observation.entity_id)
        elif observation.entity_type == "service":
            observation.entity_id = service_map.get(observation.entity_id, observation.entity_id)
        elif observation.entity_type == "web_app":
            observation.entity_id = web_map.get(observation.entity_id, observation.entity_id)
        elif observation.entity_type == "tls":
            observation.entity_id = tls_map.get(observation.entity_id, observation.entity_id)
        elif observation.entity_type == "endpoint":
            observation.entity_id = endpoint_map.get(observation.entity_id, observation.entity_id)
        elif observation.entity_type == "replay_request":
            observation.entity_id = replay_request_map.get(observation.entity_id, observation.entity_id)

        observation.evidence_ids = [evidence_map.get(evidence_id, evidence_id) for evidence_id in observation.evidence_ids]
        key = make_key(observation.entity_type, observation.entity_id, observation.key, observation.value)
        canonical_id = _canonical_id("obs", key)
        if key in existing_obs_keys:
            _append_alias(run_data, existing_obs_keys[key], observation.observation_id)
            continue
        old_id = observation.observation_id
        observation.observation_id = canonical_id
        run_data.observations.append(observation)
        existing_obs_keys[key] = observation.observation_id
        _append_alias(run_data, observation.observation_id, old_id)

    existing_endpoint_keys = {
        make_key(item.webapp_id, item.asset_id, item.service_id, item.url, item.kind): item.endpoint_id
        for item in run_data.endpoints
    }
    for endpoint in result.endpoints:
        endpoint.webapp_id = web_map.get(endpoint.webapp_id, endpoint.webapp_id)
        endpoint.asset_id = asset_map.get(endpoint.asset_id, endpoint.asset_id)
        endpoint.service_id = service_map.get(endpoint.service_id, endpoint.service_id) if endpoint.service_id else None
        key = make_key(endpoint.webapp_id, endpoint.asset_id, endpoint.service_id, endpoint.url, endpoint.kind)
        canonical_id = _canonical_id("endpoint", key)
        endpoint.canonical_key = key
        if key in existing_endpoint_keys:
            existing_id = existing_endpoint_keys[key]
            endpoint_map[endpoint.endpoint_id] = existing_id
            _append_alias(run_data, existing_id, endpoint.endpoint_id)
            continue
        old_id = endpoint.endpoint_id
        endpoint.endpoint_id = canonical_id
        run_data.endpoints.append(endpoint)
        existing_endpoint_keys[key] = endpoint.endpoint_id
        endpoint_map[old_id] = endpoint.endpoint_id
        _append_alias(run_data, endpoint.endpoint_id, old_id)

    existing_parameter_keys = {
        make_key(item.webapp_id, item.endpoint_id, item.location, item.name): item.parameter_id
        for item in run_data.parameters
    }
    for parameter in result.parameters:
        parameter.webapp_id = web_map.get(parameter.webapp_id, parameter.webapp_id)
        parameter.endpoint_id = endpoint_map.get(parameter.endpoint_id, parameter.endpoint_id) if parameter.endpoint_id else None
        key = make_key(parameter.webapp_id, parameter.endpoint_id, parameter.location, parameter.name)
        canonical_id = _canonical_id("param", key)
        parameter.canonical_key = key
        if key in existing_parameter_keys:
            _append_alias(run_data, existing_parameter_keys[key], parameter.parameter_id)
            continue
        old_id = parameter.parameter_id
        parameter.parameter_id = canonical_id
        run_data.parameters.append(parameter)
        existing_parameter_keys[key] = parameter.parameter_id
        _append_alias(run_data, parameter.parameter_id, old_id)

    existing_form_keys = {
        make_key(item.webapp_id, item.endpoint_id, item.action_url, item.method, item.field_names): item.form_id
        for item in run_data.forms
    }
    for form in result.forms:
        form.webapp_id = web_map.get(form.webapp_id, form.webapp_id)
        form.endpoint_id = endpoint_map.get(form.endpoint_id, form.endpoint_id) if form.endpoint_id else None
        key = make_key(form.webapp_id, form.endpoint_id, form.action_url, form.method, form.field_names)
        canonical_id = _canonical_id("form", key)
        form.canonical_key = key
        if key in existing_form_keys:
            _append_alias(run_data, existing_form_keys[key], form.form_id)
            continue
        old_id = form.form_id
        form.form_id = canonical_id
        run_data.forms.append(form)
        existing_form_keys[key] = form.form_id
        _append_alias(run_data, form.form_id, old_id)

    existing_login_keys = {
        make_key(item.webapp_id, item.endpoint_id, item.url, item.username_fields, item.password_fields): item.login_surface_id
        for item in run_data.login_surfaces
    }
    for login_surface in result.login_surfaces:
        login_surface.webapp_id = web_map.get(login_surface.webapp_id, login_surface.webapp_id)
        login_surface.endpoint_id = (
            endpoint_map.get(login_surface.endpoint_id, login_surface.endpoint_id)
            if login_surface.endpoint_id
            else None
        )
        key = make_key(
            login_surface.webapp_id,
            login_surface.endpoint_id,
            login_surface.url,
            login_surface.username_fields,
            login_surface.password_fields,
        )
        canonical_id = _canonical_id("login", key)
        login_surface.canonical_key = key
        if key in existing_login_keys:
            _append_alias(run_data, existing_login_keys[key], login_surface.login_surface_id)
            continue
        old_id = login_surface.login_surface_id
        login_surface.login_surface_id = canonical_id
        run_data.login_surfaces.append(login_surface)
        existing_login_keys[key] = login_surface.login_surface_id
        _append_alias(run_data, login_surface.login_surface_id, old_id)

    existing_replay_request_keys = {
        make_key(item.webapp_id, item.endpoint_id, item.url, item.method, item.parameter_names, item.tags): item.replay_request_id
        for item in run_data.replay_requests
    }
    for replay_request in result.replay_requests:
        replay_request.webapp_id = web_map.get(replay_request.webapp_id, replay_request.webapp_id)
        replay_request.asset_id = asset_map.get(replay_request.asset_id, replay_request.asset_id)
        replay_request.endpoint_id = (
            endpoint_map.get(replay_request.endpoint_id, replay_request.endpoint_id)
            if replay_request.endpoint_id
            else None
        )
        replay_request.service_id = (
            service_map.get(replay_request.service_id, replay_request.service_id)
            if replay_request.service_id
            else None
        )
        key = make_key(
            replay_request.webapp_id,
            replay_request.endpoint_id,
            replay_request.url,
            replay_request.method,
            replay_request.parameter_names,
            replay_request.tags,
        )
        canonical_id = _canonical_id("replay", key)
        replay_request.canonical_key = key
        if key in existing_replay_request_keys:
            existing_id = existing_replay_request_keys[key]
            replay_request_map[replay_request.replay_request_id] = existing_id
            _append_alias(run_data, existing_id, replay_request.replay_request_id)
            continue
        old_id = replay_request.replay_request_id
        replay_request.replay_request_id = canonical_id
        run_data.replay_requests.append(replay_request)
        existing_replay_request_keys[key] = replay_request.replay_request_id
        replay_request_map[old_id] = replay_request.replay_request_id
        _append_alias(run_data, replay_request.replay_request_id, old_id)

    existing_surface_signal_keys = {
        make_key(item.signal_key, item.signal_type, item.webapp_id, item.replay_request_id, item.parameter_name): item.surface_signal_id
        for item in run_data.surface_signals
    }
    for surface_signal in result.surface_signals:
        surface_signal.webapp_id = web_map.get(surface_signal.webapp_id, surface_signal.webapp_id)
        surface_signal.replay_request_id = (
            replay_request_map.get(surface_signal.replay_request_id, surface_signal.replay_request_id)
            if surface_signal.replay_request_id
            else None
        )
        surface_signal.endpoint_id = (
            endpoint_map.get(surface_signal.endpoint_id, surface_signal.endpoint_id)
            if surface_signal.endpoint_id
            else None
        )
        surface_signal.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in surface_signal.evidence_ids
        ]
        key = make_key(
            surface_signal.signal_key,
            surface_signal.signal_type,
            surface_signal.webapp_id,
            surface_signal.replay_request_id,
            surface_signal.parameter_name,
        )
        canonical_id = _canonical_id("signal", key)
        surface_signal.canonical_key = key
        if key in existing_surface_signal_keys:
            _append_alias(run_data, existing_surface_signal_keys[key], surface_signal.surface_signal_id)
            continue
        old_id = surface_signal.surface_signal_id
        surface_signal.surface_signal_id = canonical_id
        run_data.surface_signals.append(surface_signal)
        existing_surface_signal_keys[key] = surface_signal.surface_signal_id
        _append_alias(run_data, surface_signal.surface_signal_id, old_id)

    existing_response_delta_keys = {
        make_key(item.replay_request_id, item.attack_path_id, item.step_key, item.comparison_type, item.summary): item.response_delta_id
        for item in run_data.response_deltas
    }
    for response_delta in result.response_deltas:
        response_delta.replay_request_id = replay_request_map.get(
            response_delta.replay_request_id,
            response_delta.replay_request_id,
        )
        response_delta.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in response_delta.evidence_ids
        ]
        key = make_key(
            response_delta.replay_request_id,
            response_delta.attack_path_id,
            response_delta.step_key,
            response_delta.comparison_type,
            response_delta.summary,
        )
        canonical_id = _canonical_id("delta", key)
        response_delta.canonical_key = key
        if key in existing_response_delta_keys:
            _append_alias(run_data, existing_response_delta_keys[key], response_delta.response_delta_id)
            continue
        old_id = response_delta.response_delta_id
        response_delta.response_delta_id = canonical_id
        run_data.response_deltas.append(response_delta)
        existing_response_delta_keys[key] = response_delta.response_delta_id
        _append_alias(run_data, response_delta.response_delta_id, old_id)

    existing_authz_keys = {
        make_key(item.attack_path_id, item.replay_request_id, item.parameter_name, item.outcome): item.authorization_comparison_id
        for item in run_data.authorization_comparisons
    }
    for authorization_comparison in result.authorization_comparisons:
        authorization_comparison.replay_request_id = replay_request_map.get(
            authorization_comparison.replay_request_id,
            authorization_comparison.replay_request_id,
        )
        authorization_comparison.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id)
            for evidence_id in authorization_comparison.evidence_ids
        ]
        key = make_key(
            authorization_comparison.attack_path_id,
            authorization_comparison.replay_request_id,
            authorization_comparison.parameter_name,
            authorization_comparison.outcome,
        )
        canonical_id = _canonical_id("authz", key)
        authorization_comparison.canonical_key = key
        if key in existing_authz_keys:
            _append_alias(
                run_data,
                existing_authz_keys[key],
                authorization_comparison.authorization_comparison_id,
            )
            continue
        old_id = authorization_comparison.authorization_comparison_id
        authorization_comparison.authorization_comparison_id = canonical_id
        run_data.authorization_comparisons.append(authorization_comparison)
        existing_authz_keys[key] = authorization_comparison.authorization_comparison_id
        _append_alias(run_data, authorization_comparison.authorization_comparison_id, old_id)

    existing_proof_outcome_keys = {
        make_key(item.attack_path_id, item.playbook_key, item.step_key, item.status, item.reason): item.proof_outcome_id
        for item in run_data.proof_outcomes
    }
    for proof_outcome in result.proof_outcomes:
        proof_outcome.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in proof_outcome.evidence_ids
        ]
        key = make_key(
            proof_outcome.attack_path_id,
            proof_outcome.playbook_key,
            proof_outcome.step_key,
            proof_outcome.status,
            proof_outcome.reason,
        )
        canonical_id = _canonical_id("proof", key)
        proof_outcome.canonical_key = key
        if key in existing_proof_outcome_keys:
            _append_alias(run_data, existing_proof_outcome_keys[key], proof_outcome.proof_outcome_id)
            continue
        old_id = proof_outcome.proof_outcome_id
        proof_outcome.proof_outcome_id = canonical_id
        run_data.proof_outcomes.append(proof_outcome)
        existing_proof_outcome_keys[key] = proof_outcome.proof_outcome_id
        _append_alias(run_data, proof_outcome.proof_outcome_id, old_id)

    existing_validation_keys = {
        make_key(item.replay_request_id, item.validator_key, item.status, item.request_url, item.title): item.validation_result_id
        for item in run_data.validation_results
    }
    for validation_result in result.validation_results:
        validation_result.webapp_id = web_map.get(validation_result.webapp_id, validation_result.webapp_id)
        validation_result.replay_request_id = replay_request_map.get(
            validation_result.replay_request_id,
            validation_result.replay_request_id,
        )
        validation_result.entry_signal_ids = list(validation_result.entry_signal_ids)
        validation_result.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in validation_result.evidence_ids
        ]
        key = make_key(
            validation_result.replay_request_id,
            validation_result.validator_key,
            validation_result.status,
            validation_result.request_url,
            validation_result.title,
        )
        canonical_id = _canonical_id("vresult", key)
        validation_result.canonical_key = key
        if key in existing_validation_keys:
            _append_alias(run_data, existing_validation_keys[key], validation_result.validation_result_id)
            continue
        old_id = validation_result.validation_result_id
        validation_result.validation_result_id = canonical_id
        run_data.validation_results.append(validation_result)
        existing_validation_keys[key] = validation_result.validation_result_id
        _append_alias(run_data, validation_result.validation_result_id, old_id)

    existing_playbook_execution_keys = {
        make_key(item.attack_path_id, item.playbook_key, item.status, item.next_step_id): item.playbook_execution_id
        for item in run_data.playbook_executions
    }
    for playbook_execution in result.playbook_executions:
        playbook_execution.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in playbook_execution.evidence_ids
        ]
        key = make_key(
            playbook_execution.attack_path_id,
            playbook_execution.playbook_key,
            playbook_execution.status,
            playbook_execution.next_step_id,
        )
        canonical_id = _canonical_id("playbook", key)
        playbook_execution.canonical_key = key
        if key in existing_playbook_execution_keys:
            _append_alias(
                run_data,
                existing_playbook_execution_keys[key],
                playbook_execution.playbook_execution_id,
            )
            continue
        old_id = playbook_execution.playbook_execution_id
        playbook_execution.playbook_execution_id = canonical_id
        run_data.playbook_executions.append(playbook_execution)
        existing_playbook_execution_keys[key] = playbook_execution.playbook_execution_id
        _append_alias(run_data, playbook_execution.playbook_execution_id, old_id)

    existing_coverage_decision_keys = {
        make_key(item.attack_path_id, item.playbook_key, item.status, item.reason): item.coverage_decision_id
        for item in run_data.coverage_decisions
    }
    for coverage_decision in result.coverage_decisions:
        coverage_decision.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in coverage_decision.evidence_ids
        ]
        key = make_key(
            coverage_decision.attack_path_id,
            coverage_decision.playbook_key,
            coverage_decision.status,
            coverage_decision.reason,
        )
        canonical_id = _canonical_id("cdecision", key)
        coverage_decision.canonical_key = key
        if key in existing_coverage_decision_keys:
            _append_alias(
                run_data,
                existing_coverage_decision_keys[key],
                coverage_decision.coverage_decision_id,
            )
            continue
        old_id = coverage_decision.coverage_decision_id
        coverage_decision.coverage_decision_id = canonical_id
        run_data.coverage_decisions.append(coverage_decision)
        existing_coverage_decision_keys[key] = coverage_decision.coverage_decision_id
        _append_alias(run_data, coverage_decision.coverage_decision_id, old_id)

    existing_hypothesis_keys = {
        make_key(item.title, item.exploit_class, item.affected_entities): item.hypothesis_id
        for item in run_data.hypotheses
    }
    for hypothesis in result.hypotheses:
        key = make_key(hypothesis.title, hypothesis.exploit_class, hypothesis.affected_entities)
        canonical_id = _canonical_id("hypothesis", key)
        if key in existing_hypothesis_keys:
            _append_alias(run_data, existing_hypothesis_keys[key], hypothesis.hypothesis_id)
            continue
        old_id = hypothesis.hypothesis_id
        hypothesis.hypothesis_id = canonical_id
        run_data.hypotheses.append(hypothesis)
        existing_hypothesis_keys[key] = hypothesis.hypothesis_id
        _append_alias(run_data, hypothesis.hypothesis_id, old_id)

    existing_step_keys = {
        make_key(item.attack_path_id, item.playbook_key, item.step_key, item.title, item.status): item.investigation_step_id
        for item in run_data.investigation_steps
    }
    for investigation_step in result.investigation_steps:
        investigation_step.evidence_ids = [
            evidence_map.get(evidence_id, evidence_id) for evidence_id in investigation_step.evidence_ids
        ]
        key = make_key(
            investigation_step.attack_path_id,
            investigation_step.playbook_key,
            investigation_step.step_key,
            investigation_step.title,
            investigation_step.status,
        )
        canonical_id = _canonical_id("step", key)
        investigation_step.canonical_key = key
        if key in existing_step_keys:
            _append_alias(run_data, existing_step_keys[key], investigation_step.investigation_step_id)
            continue
        old_id = investigation_step.investigation_step_id
        investigation_step.investigation_step_id = canonical_id
        run_data.investigation_steps.append(investigation_step)
        existing_step_keys[key] = investigation_step.investigation_step_id
        _append_alias(run_data, investigation_step.investigation_step_id, old_id)

    existing_validation_task_keys = {
        make_key(item.hypothesis_id, item.title, item.task_key, item.status): item.validation_task_id
        for item in run_data.validation_tasks
    }
    for validation_task in result.validation_tasks:
        key = make_key(validation_task.hypothesis_id, validation_task.title, validation_task.task_key, validation_task.status)
        canonical_id = _canonical_id("vtask", key)
        if key in existing_validation_task_keys:
            _append_alias(run_data, existing_validation_task_keys[key], validation_task.validation_task_id)
            continue
        old_id = validation_task.validation_task_id
        validation_task.validation_task_id = canonical_id
        run_data.validation_tasks.append(validation_task)
        existing_validation_task_keys[key] = validation_task.validation_task_id
        _append_alias(run_data, validation_task.validation_task_id, old_id)

    existing_gap_keys = {
        make_key(item.title, item.reason, item.url, item.affected_entities): item.coverage_gap_id
        for item in run_data.coverage_gaps
    }
    for coverage_gap in result.coverage_gaps:
        coverage_gap.evidence_ids = [evidence_map.get(evidence_id, evidence_id) for evidence_id in coverage_gap.evidence_ids]
        key = make_key(coverage_gap.title, coverage_gap.reason, coverage_gap.url, coverage_gap.affected_entities)
        canonical_id = _canonical_id("gap", key)
        if key in existing_gap_keys:
            _append_alias(run_data, existing_gap_keys[key], coverage_gap.coverage_gap_id)
            continue
        old_id = coverage_gap.coverage_gap_id
        coverage_gap.coverage_gap_id = canonical_id
        run_data.coverage_gaps.append(coverage_gap)
        existing_gap_keys[key] = coverage_gap.coverage_gap_id
        _append_alias(run_data, coverage_gap.coverage_gap_id, old_id)

    run_data.tool_executions.extend(result.tool_executions)
    _register_evidence_artifacts(run_data, result.evidence_artifacts)
    normalized_entities = list(result.normalized_entities)
    normalized_entities.extend(_legacy_entities_to_normalized(result))
    _register_normalized_entities(run_data, normalized_entities)
    _register_task_results(run_data, result.task_results)
    run_data.warnings.extend(result.warnings)
    run_data.errors.extend(result.errors)
    run_data.facts = _merge_facts(run_data.facts, result.facts)
    _create_assertions(run_data)
