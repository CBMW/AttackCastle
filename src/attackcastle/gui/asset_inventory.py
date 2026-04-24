from __future__ import annotations

import json
from ipaddress import ip_address
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from attackcastle.gui.models import EntityNote, RunSnapshot


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _clean(value).lower()


def _normalize_url(value: Any) -> str:
    raw = _clean(value)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.scheme and not parts.netloc:
        return raw
    scheme = parts.scheme.lower()
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        host = ""
        port = None
    if host:
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = {"http": 80, "https": 443}.get(scheme)
        netloc = f"{host}:{port}" if port and port != default_port else host
    else:
        netloc = parts.netloc.lower()
    query = urlencode(
        sorted(parse_qsl(parts.query, keep_blank_values=True)),
        doseq=True,
    )
    return urlunsplit(
        (
            scheme,
            netloc,
            parts.path or "/",
            query,
            "",
        )
    )


def _asset_lookup(snapshot: RunSnapshot) -> dict[str, dict[str, Any]]:
    return {str(item.get("asset_id") or ""): item for item in snapshot.assets if str(item.get("asset_id") or "").strip()}


def _service_lookup(snapshot: RunSnapshot) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("service_id") or ""): item
        for item in snapshot.services
        if str(item.get("service_id") or "").strip()
    }


def _webapp_lookup(snapshot: RunSnapshot) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("webapp_id") or ""): item
        for item in snapshot.web_apps
        if str(item.get("webapp_id") or "").strip()
    }


def _endpoint_lookup(snapshot: RunSnapshot) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("endpoint_id") or ""): item
        for item in snapshot.endpoints
        if str(item.get("endpoint_id") or "").strip()
    }


def _normalize_ip(value: Any) -> str:
    text = _clean(value)
    if not text:
        return ""
    try:
        return str(ip_address(text))
    except ValueError:
        return ""


def _is_ip_literal(value: Any) -> bool:
    return bool(_normalize_ip(value))


def _append_unique(values: list[str], value: Any) -> None:
    text = _clean(value)
    if text and text not in values:
        values.append(text)


def _asset_ip_values(row: dict[str, Any], assets_by_id: dict[str, dict[str, Any]]) -> list[str]:
    values: list[str] = []
    ip = _normalize_ip(row.get("ip"))
    if ip:
        values.append(ip)
    resolved_ips = row.get("resolved_ips")
    if isinstance(resolved_ips, (list, tuple, set)):
        for item in resolved_ips:
            normalized = _normalize_ip(item)
            if normalized and normalized not in values:
                values.append(normalized)
    asset_id = _clean(row.get("asset_id"))
    if asset_id:
        for child in assets_by_id.values():
            if _clean(child.get("parent_asset_id")) != asset_id:
                continue
            for item in _asset_ip_values(child, {}):
                if item not in values:
                    values.append(item)
    return values


def _single_asset_ip(row: dict[str, Any], assets_by_id: dict[str, dict[str, Any]]) -> str:
    values = _asset_ip_values(row, assets_by_id)
    return values[0] if len(values) == 1 else ""


def _asset_alias_values(row: dict[str, Any], assets_by_id: dict[str, dict[str, Any]]) -> list[str]:
    aliases: list[str] = []
    raw_aliases = row.get("aliases")
    if isinstance(raw_aliases, (list, tuple, set)):
        for alias in raw_aliases:
            _append_unique(aliases, alias)
    asset_id = _clean(row.get("asset_id"))
    if asset_id:
        for child in assets_by_id.values():
            if _clean(child.get("parent_asset_id")) != asset_id:
                continue
            child_name = _clean(child.get("name"))
            if child_name and not _is_ip_literal(child_name):
                _append_unique(aliases, child_name)
            child_aliases = child.get("aliases")
            if isinstance(child_aliases, (list, tuple, set)):
                for alias in child_aliases:
                    _append_unique(aliases, alias)
    return aliases


def _asset_signature_for_row(
    row: dict[str, Any],
    assets_by_id: dict[str, dict[str, Any]],
    *,
    visited: set[str] | None = None,
) -> str:
    ip = _single_asset_ip(row, assets_by_id)
    if ip:
        return "|".join(("asset", "ip", ip))
    canonical_key = _lower(row.get("canonical_key"))
    if canonical_key:
        return "|".join(("asset", "canonical", canonical_key))
    asset_id = _clean(row.get("asset_id"))
    seen = visited or set()
    if asset_id and asset_id in seen:
        return ""
    if asset_id:
        seen = set(seen)
        seen.add(asset_id)
    parent_signature = ""
    parent_asset_id = _clean(row.get("parent_asset_id"))
    parent_row = assets_by_id.get(parent_asset_id)
    if parent_row is not None:
        parent_signature = _asset_signature_for_row(parent_row, assets_by_id, visited=seen)
    return "|".join(
        (
            "asset",
            _lower(row.get("kind")),
            _lower(row.get("name")),
            _clean(row.get("ip")),
            parent_signature,
        )
    )


def entity_signature(entity_kind: str, row: dict[str, Any], snapshot: RunSnapshot) -> str:
    assets_by_id = _asset_lookup(snapshot)
    services_by_id = _service_lookup(snapshot)
    endpoint_by_id = _endpoint_lookup(snapshot)

    if entity_kind == "asset":
        return _asset_signature_for_row(row, assets_by_id)

    if entity_kind == "service":
        asset_row = assets_by_id.get(_clean(row.get("asset_id")), {})
        return "|".join(
            (
                "service",
                _asset_signature_for_row(asset_row, assets_by_id),
                _clean(row.get("port")),
                _lower(row.get("protocol")),
                _lower(row.get("name")),
            )
        )

    if entity_kind == "web_app":
        return "|".join(
            (
                "web_app",
                _normalize_url(row.get("url")),
            )
        )

    if entity_kind == "endpoint":
        return "|".join(
            (
                "endpoint",
                _lower(row.get("kind")),
                _clean(row.get("method")).upper(),
                _normalize_url(row.get("url")),
            )
        )

    if entity_kind == "parameter":
        endpoint_row = endpoint_by_id.get(_clean(row.get("endpoint_id")), {})
        return "|".join(
            (
                "parameter",
                _normalize_url(endpoint_row.get("url")),
                _clean(endpoint_row.get("method")).upper(),
                _lower(row.get("name")),
                _lower(row.get("location")),
            )
        )

    if entity_kind == "form":
        return "|".join(
            (
                "form",
                _clean(row.get("method")).upper(),
                _normalize_url(row.get("action_url")),
            )
        )

    if entity_kind == "login_surface":
        return "|".join(("login_surface", _normalize_url(row.get("url"))))

    if entity_kind == "site_map":
        return "|".join(
            (
                "site_map",
                _lower(row.get("source")),
                _normalize_url(row.get("url")),
            )
        )

    if entity_kind == "technology":
        asset_row = assets_by_id.get(_clean(row.get("asset_id")), {})
        return "|".join(
            (
                "technology",
                _asset_signature_for_row(asset_row, assets_by_id),
                _lower(row.get("name")),
                _lower(row.get("version")),
                _lower(row.get("category")),
            )
        )

    if entity_kind == "route":
        return "|".join(("route", _normalize_url(row.get("url"))))

    service_row = services_by_id.get(_clean(row.get("service_id")), {})
    asset_row = assets_by_id.get(_clean(row.get("asset_id")) or _clean(service_row.get("asset_id")), {})
    return "|".join(
        (
            _lower(entity_kind),
            _asset_signature_for_row(asset_row, assets_by_id),
            _normalize_url(row.get("url") or row.get("action_url")),
            _lower(row.get("name")),
        )
    )


def row_label(entity_kind: str, row: dict[str, Any], snapshot: RunSnapshot) -> str:
    if entity_kind == "asset":
        return _clean(row.get("name")) or _clean(row.get("ip")) or "Asset"
    if entity_kind == "service":
        target = scan_target_for_row(entity_kind, row, snapshot)
        service_name = _clean(row.get("name")) or f"{_clean(row.get('protocol')).upper()}:{_clean(row.get('port'))}"
        return f"{service_name} on {target}".strip()
    if entity_kind == "web_app":
        return _clean(row.get("url")) or "Web App"
    if entity_kind == "endpoint":
        method = _clean(row.get("method")).upper()
        url = _clean(row.get("url"))
        return f"{method} {url}".strip()
    if entity_kind == "parameter":
        return _clean(row.get("name")) or "Parameter"
    if entity_kind == "form":
        return _clean(row.get("action_url")) or "Form"
    if entity_kind == "login_surface":
        return _clean(row.get("url")) or "Login Surface"
    if entity_kind == "site_map":
        return _clean(row.get("url")) or "Route"
    if entity_kind == "technology":
        return _clean(row.get("name")) or "Technology"
    return _clean(row.get("name")) or _clean(row.get("url")) or entity_kind.title()


def asset_discovery_source(row: dict[str, Any]) -> str:
    kind = _lower(row.get("kind"))
    source_tool = _lower(row.get("source_tool"))
    source = _lower(row.get("source"))

    if kind == "scope_target" or source_tool == "scope_parser" or source == "scope_item":
        return "Scope Item"

    attacker_markers = (
        "attacker",
        "manual",
        "browser",
        "replay",
        "metasploit",
    )
    if any(marker in source_tool for marker in attacker_markers) or any(marker in source for marker in attacker_markers):
        return "Attacker"

    if source_tool == "internal" or source == "internal":
        return "Internal"

    if source_tool or source or kind:
        return "Scanner"

    return "Internal"


def scan_target_for_row(entity_kind: str, row: dict[str, Any], snapshot: RunSnapshot) -> str:
    assets_by_id = _asset_lookup(snapshot)
    services_by_id = _service_lookup(snapshot)
    endpoint_by_id = _endpoint_lookup(snapshot)

    if entity_kind == "asset":
        return _clean(row.get("ip")) or _clean(row.get("name"))

    if entity_kind == "service":
        asset_row = assets_by_id.get(_clean(row.get("asset_id")), {})
        host = _clean(asset_row.get("ip")) or _clean(asset_row.get("name"))
        port = _clean(row.get("port"))
        return f"{host}:{port}" if host and port else host

    if entity_kind == "web_app":
        return _clean(row.get("url"))

    if entity_kind == "endpoint":
        return _clean(row.get("url"))

    if entity_kind == "parameter":
        endpoint_row = endpoint_by_id.get(_clean(row.get("endpoint_id")), {})
        return _clean(endpoint_row.get("url"))

    if entity_kind == "form":
        return _clean(row.get("action_url"))

    if entity_kind == "login_surface":
        return _clean(row.get("url"))

    if entity_kind == "site_map":
        return _clean(row.get("url"))

    if entity_kind == "technology":
        asset_row = assets_by_id.get(_clean(row.get("asset_id")), {})
        return _clean(asset_row.get("ip")) or _clean(asset_row.get("name"))

    service_row = services_by_id.get(_clean(row.get("service_id")), {})
    if service_row:
        return scan_target_for_row("service", service_row, snapshot)
    return _clean(row.get("url")) or _clean(row.get("name"))


def build_entity_note(entity_kind: str, row: dict[str, Any], snapshot: RunSnapshot, text: str) -> EntityNote:
    return EntityNote(
        signature=entity_signature(entity_kind, row, snapshot),
        entity_kind=entity_kind,
        label=row_label(entity_kind, row, snapshot),
        note=str(text or "").strip(),
        target=scan_target_for_row(entity_kind, row, snapshot),
    )


def build_detail_payload(
    entity_kind: str,
    row: dict[str, Any],
    snapshot: RunSnapshot,
    note: EntityNote | None = None,
) -> dict[str, Any]:
    assets_by_id = _asset_lookup(snapshot)
    services_by_id = _service_lookup(snapshot)
    webapps_by_id = _webapp_lookup(snapshot)

    payload: dict[str, Any] = {
        "entity_kind": entity_kind,
        "label": row_label(entity_kind, row, snapshot),
        "target": scan_target_for_row(entity_kind, row, snapshot),
        "record": dict(row),
    }
    if note is not None and note.note.strip():
        payload["note"] = note.note.strip()
        payload["note_updated_at"] = note.updated_at

    if entity_kind == "asset":
        asset_id = _clean(row.get("asset_id"))
        payload["related_services"] = [item for item in snapshot.services if _clean(item.get("asset_id")) == asset_id]
        payload["related_web_apps"] = [item for item in snapshot.web_apps if _clean(item.get("asset_id")) == asset_id]
        payload["related_technologies"] = [item for item in snapshot.technologies if _clean(item.get("asset_id")) == asset_id]
        related_webapp_ids = {
            _clean(item.get("webapp_id"))
            for item in payload["related_web_apps"]
            if _clean(item.get("webapp_id"))
        }
        payload["related_routes"] = [item for item in snapshot.site_map if _clean(item.get("entity_id")) in related_webapp_ids]
        return payload

    if entity_kind == "service":
        service_id = _clean(row.get("service_id"))
        asset_row = assets_by_id.get(_clean(row.get("asset_id")))
        if asset_row is not None:
            payload["asset"] = asset_row
        payload["related_web_apps"] = [item for item in snapshot.web_apps if _clean(item.get("service_id")) == service_id]
        return payload

    if entity_kind == "web_app":
        webapp_id = _clean(row.get("webapp_id"))
        if _clean(row.get("asset_id")) in assets_by_id:
            payload["asset"] = assets_by_id[_clean(row.get("asset_id"))]
        if _clean(row.get("service_id")) in services_by_id:
            payload["service"] = services_by_id[_clean(row.get("service_id"))]
        payload["related_endpoints"] = [item for item in snapshot.endpoints if _clean(item.get("webapp_id")) == webapp_id]
        payload["related_parameters"] = [item for item in snapshot.parameters if _clean(item.get("webapp_id")) == webapp_id]
        payload["related_forms"] = [item for item in snapshot.forms if _clean(item.get("webapp_id")) == webapp_id]
        payload["related_login_surfaces"] = [item for item in snapshot.login_surfaces if _normalize_url(item.get("url")) == _normalize_url(row.get("url"))]
        payload["related_routes"] = [item for item in snapshot.site_map if _clean(item.get("entity_id")) == webapp_id]
        return payload

    asset_id = _clean(row.get("asset_id"))
    service_id = _clean(row.get("service_id"))
    webapp_id = _clean(row.get("webapp_id"))
    if asset_id in assets_by_id:
        payload["asset"] = assets_by_id[asset_id]
    if service_id in services_by_id:
        payload["service"] = services_by_id[service_id]
    if webapp_id in webapps_by_id:
        payload["web_app"] = webapps_by_id[webapp_id]
    return payload


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return True


def _merge_list_values(existing: list[Any], incoming: list[Any]) -> list[Any]:
    merged: list[Any] = []
    seen: set[str] = set()
    for item in [*existing, *incoming]:
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def _stable_row_key(row: dict[str, Any], fallback_fields: tuple[str, ...]) -> str:
    for field in fallback_fields:
        value = _clean(row.get(field))
        if value:
            return value
    return json.dumps(row, sort_keys=True, default=str)


def _merge_generic_rows(
    rows_by_key: dict[str, dict[str, Any]],
    rows: list[dict[str, Any]],
    *,
    key_fields: tuple[str, ...],
) -> None:
    for row in rows:
        key = _stable_row_key(row, key_fields)
        aggregate_row = dict(row)
        rows_by_key[key] = (
            _merge_inventory_row(rows_by_key[key], aggregate_row)
            if key in rows_by_key
            else aggregate_row
        )


def _merge_inventory_row(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, incoming_value in incoming.items():
        if key not in merged:
            merged[key] = incoming_value
            continue
        current_value = merged[key]
        if (
            key == "name"
            and _is_ip_literal(current_value)
            and _has_value(incoming_value)
            and not _is_ip_literal(incoming_value)
        ):
            merged[key] = incoming_value
            continue
        if (
            key == "name"
            and _has_value(current_value)
            and _has_value(incoming_value)
            and current_value != incoming_value
            and not _is_ip_literal(incoming_value)
        ):
            aliases = merged.get("aliases")
            alias_values = list(aliases) if isinstance(aliases, list) else []
            _append_unique(alias_values, incoming_value)
            merged["aliases"] = alias_values
            continue
        if isinstance(current_value, list) and isinstance(incoming_value, list):
            merged[key] = _merge_list_values(current_value, incoming_value)
            continue
        if isinstance(current_value, dict) and isinstance(incoming_value, dict):
            nested = dict(current_value)
            nested.update({nested_key: nested_value for nested_key, nested_value in incoming_value.items() if _has_value(nested_value)})
            merged[key] = nested
            continue
        if isinstance(current_value, bool) and isinstance(incoming_value, bool):
            merged[key] = current_value or incoming_value
            continue
        if not _has_value(current_value) and _has_value(incoming_value):
            merged[key] = incoming_value
    return merged


def _copy_row(row: dict[str, Any], **updates: Any) -> dict[str, Any]:
    copied = dict(row)
    copied.update({key: value for key, value in updates.items() if value is not None})
    return copied


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _asset_inventory_row(row: dict[str, Any], assets_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    aggregate_row = dict(row)
    ips = _asset_ip_values(row, assets_by_id)
    if ips:
        aggregate_row["resolved_ips"] = ips
    single_ip = ips[0] if len(ips) == 1 else ""
    if single_ip and not _clean(aggregate_row.get("ip")):
        aggregate_row["ip"] = single_ip
    aliases = _asset_alias_values(row, assets_by_id)
    if aliases:
        aggregate_row["aliases"] = aliases
    return aggregate_row


def build_workspace_inventory_snapshot(
    snapshots: list[RunSnapshot],
    *,
    workspace_id: str = "",
    workspace_name: str = "",
) -> RunSnapshot | None:
    ordered = [snapshot for snapshot in snapshots if snapshot is not None]
    if not ordered:
        return None

    canonical_workspace_id = workspace_id or next(
        (snapshot.workspace_id for snapshot in ordered if snapshot.workspace_id),
        "",
    )
    canonical_workspace_name = workspace_name or next(
        (snapshot.workspace_name for snapshot in ordered if snapshot.workspace_name),
        "",
    )

    scope_rows: dict[str, dict[str, Any]] = {}
    asset_rows: dict[str, dict[str, Any]] = {}
    service_rows: dict[str, dict[str, Any]] = {}
    web_app_rows: dict[str, dict[str, Any]] = {}
    tls_rows: dict[str, dict[str, Any]] = {}
    endpoint_rows: dict[str, dict[str, Any]] = {}
    parameter_rows: dict[str, dict[str, Any]] = {}
    form_rows: dict[str, dict[str, Any]] = {}
    login_surface_rows: dict[str, dict[str, Any]] = {}
    site_map_rows: dict[str, dict[str, Any]] = {}
    technology_rows: dict[str, dict[str, Any]] = {}
    finding_rows: dict[str, dict[str, Any]] = {}
    screenshot_rows: dict[str, dict[str, Any]] = {}
    bundle_rows: dict[str, dict[str, Any]] = {}
    relationship_rows: dict[str, dict[str, Any]] = {}
    tool_execution_rows: dict[str, dict[str, Any]] = {}

    asset_id_map: dict[tuple[str, str], str] = {}
    service_id_map: dict[tuple[str, str], str] = {}
    webapp_id_map: dict[tuple[str, str], str] = {}
    endpoint_id_map: dict[tuple[str, str], str] = {}

    for snapshot in ordered:
        _merge_generic_rows(scope_rows, snapshot.scope, key_fields=("target_id", "raw", "value"))
        assets_by_id = {
            _clean(item.get("asset_id")): item
            for item in snapshot.assets
            if _clean(item.get("asset_id"))
        }
        services_by_id = {
            _clean(item.get("service_id")): item
            for item in snapshot.services
            if _clean(item.get("service_id"))
        }
        webapps_by_id = {
            _clean(item.get("webapp_id")): item
            for item in snapshot.web_apps
            if _clean(item.get("webapp_id"))
        }
        endpoints_by_id = {
            _clean(item.get("endpoint_id")): item
            for item in snapshot.endpoints
            if _clean(item.get("endpoint_id"))
        }

        for row in snapshot.assets:
            signature = _asset_signature_for_row(row, assets_by_id)
            if not signature:
                continue
            old_asset_id = _clean(row.get("asset_id"))
            if old_asset_id:
                asset_id_map[(snapshot.run_id, old_asset_id)] = signature
            parent_row = assets_by_id.get(_clean(row.get("parent_asset_id")))
            parent_signature = _asset_signature_for_row(parent_row, assets_by_id) if parent_row is not None else ""
            if parent_signature == signature:
                parent_signature = ""
            aggregate_row = _copy_row(
                _asset_inventory_row(row, assets_by_id),
                asset_id=signature,
                parent_asset_id=parent_signature,
            )
            asset_rows[signature] = (
                _merge_inventory_row(asset_rows[signature], aggregate_row)
                if signature in asset_rows
                else aggregate_row
            )

        for row in snapshot.services:
            signature = entity_signature("service", row, snapshot)
            if not signature:
                continue
            old_service_id = _clean(row.get("service_id"))
            if old_service_id:
                service_id_map[(snapshot.run_id, old_service_id)] = signature
            aggregate_row = _copy_row(
                row,
                service_id=signature,
                asset_id=asset_id_map.get((snapshot.run_id, _clean(row.get("asset_id"))), ""),
            )
            service_rows[signature] = (
                _merge_inventory_row(service_rows[signature], aggregate_row)
                if signature in service_rows
                else aggregate_row
            )

        for row in snapshot.web_apps:
            signature = entity_signature("web_app", row, snapshot)
            if not signature:
                continue
            old_webapp_id = _clean(row.get("webapp_id"))
            if old_webapp_id:
                webapp_id_map[(snapshot.run_id, old_webapp_id)] = signature
            aggregate_row = _copy_row(
                row,
                webapp_id=signature,
                asset_id=asset_id_map.get((snapshot.run_id, _clean(row.get("asset_id"))), ""),
                service_id=service_id_map.get((snapshot.run_id, _clean(row.get("service_id"))), ""),
            )
            web_app_rows[signature] = (
                _merge_inventory_row(web_app_rows[signature], aggregate_row)
                if signature in web_app_rows
                else aggregate_row
            )

        for row in snapshot.tls_assets:
            key = _stable_row_key(row, ("tls_id", "canonical_key", "host"))
            service_row = services_by_id.get(_clean(row.get("service_id"))) or {}
            aggregate_row = _copy_row(
                row,
                asset_id=asset_id_map.get((snapshot.run_id, _clean(row.get("asset_id"))), ""),
                service_id=service_id_map.get(
                    (snapshot.run_id, _clean(row.get("service_id")) or _clean(service_row.get("service_id"))),
                    "",
                ),
            )
            tls_rows[key] = (
                _merge_inventory_row(tls_rows[key], aggregate_row)
                if key in tls_rows
                else aggregate_row
            )

        for row in snapshot.endpoints:
            signature = entity_signature("endpoint", row, snapshot)
            if not signature:
                continue
            old_endpoint_id = _clean(row.get("endpoint_id"))
            if old_endpoint_id:
                endpoint_id_map[(snapshot.run_id, old_endpoint_id)] = signature
            service_row = services_by_id.get(_clean(row.get("service_id"))) or {}
            aggregate_row = _copy_row(
                row,
                endpoint_id=signature,
                asset_id=asset_id_map.get(
                    (snapshot.run_id, _clean(row.get("asset_id")) or _clean(service_row.get("asset_id"))),
                    "",
                ),
                service_id=service_id_map.get((snapshot.run_id, _clean(row.get("service_id"))), ""),
                webapp_id=webapp_id_map.get((snapshot.run_id, _clean(row.get("webapp_id"))), ""),
            )
            endpoint_rows[signature] = (
                _merge_inventory_row(endpoint_rows[signature], aggregate_row)
                if signature in endpoint_rows
                else aggregate_row
            )

        for row in snapshot.parameters:
            signature = entity_signature("parameter", row, snapshot)
            if not signature:
                continue
            endpoint_row = endpoints_by_id.get(_clean(row.get("endpoint_id"))) or {}
            service_row = services_by_id.get(_clean(row.get("service_id")) or _clean(endpoint_row.get("service_id"))) or {}
            aggregate_row = _copy_row(
                row,
                parameter_id=signature,
                endpoint_id=endpoint_id_map.get((snapshot.run_id, _clean(row.get("endpoint_id"))), ""),
                webapp_id=webapp_id_map.get((snapshot.run_id, _clean(row.get("webapp_id"))), ""),
                service_id=service_id_map.get(
                    (snapshot.run_id, _clean(row.get("service_id")) or _clean(endpoint_row.get("service_id"))),
                    "",
                ),
                asset_id=asset_id_map.get(
                    (
                        snapshot.run_id,
                        _clean(row.get("asset_id"))
                        or _clean(endpoint_row.get("asset_id"))
                        or _clean(service_row.get("asset_id")),
                    ),
                    "",
                ),
            )
            parameter_rows[signature] = (
                _merge_inventory_row(parameter_rows[signature], aggregate_row)
                if signature in parameter_rows
                else aggregate_row
            )

        for row in snapshot.forms:
            signature = entity_signature("form", row, snapshot)
            if not signature:
                continue
            service_row = services_by_id.get(_clean(row.get("service_id"))) or {}
            aggregate_row = _copy_row(
                row,
                form_id=signature,
                webapp_id=webapp_id_map.get((snapshot.run_id, _clean(row.get("webapp_id"))), ""),
                service_id=service_id_map.get((snapshot.run_id, _clean(row.get("service_id"))), ""),
                asset_id=asset_id_map.get(
                    (snapshot.run_id, _clean(row.get("asset_id")) or _clean(service_row.get("asset_id"))),
                    "",
                ),
            )
            form_rows[signature] = (
                _merge_inventory_row(form_rows[signature], aggregate_row)
                if signature in form_rows
                else aggregate_row
            )

        for row in snapshot.login_surfaces:
            signature = entity_signature("login_surface", row, snapshot)
            if not signature:
                continue
            webapp_row = webapps_by_id.get(_clean(row.get("webapp_id"))) or {}
            service_row = services_by_id.get(_clean(row.get("service_id")) or _clean(webapp_row.get("service_id"))) or {}
            aggregate_row = _copy_row(
                row,
                login_surface_id=signature,
                webapp_id=webapp_id_map.get((snapshot.run_id, _clean(row.get("webapp_id"))), ""),
                service_id=service_id_map.get(
                    (snapshot.run_id, _clean(row.get("service_id")) or _clean(webapp_row.get("service_id"))),
                    "",
                ),
                asset_id=asset_id_map.get(
                    (
                        snapshot.run_id,
                        _clean(row.get("asset_id"))
                        or _clean(webapp_row.get("asset_id"))
                        or _clean(service_row.get("asset_id")),
                    ),
                    "",
                ),
            )
            login_surface_rows[signature] = (
                _merge_inventory_row(login_surface_rows[signature], aggregate_row)
                if signature in login_surface_rows
                else aggregate_row
            )

        for row in snapshot.site_map:
            signature = entity_signature("site_map", row, snapshot)
            if not signature:
                continue
            aggregate_row = _copy_row(
                row,
                entity_id=webapp_id_map.get((snapshot.run_id, _clean(row.get("entity_id"))), ""),
            )
            site_map_rows[signature] = (
                _merge_inventory_row(site_map_rows[signature], aggregate_row)
                if signature in site_map_rows
                else aggregate_row
            )

        for row in snapshot.technologies:
            signature = entity_signature("technology", row, snapshot)
            if not signature:
                continue
            webapp_row = webapps_by_id.get(_clean(row.get("webapp_id"))) or {}
            service_row = services_by_id.get(_clean(row.get("service_id")) or _clean(webapp_row.get("service_id"))) or {}
            aggregate_row = _copy_row(
                row,
                tech_id=signature,
                asset_id=asset_id_map.get(
                    (
                        snapshot.run_id,
                        _clean(row.get("asset_id"))
                        or _clean(webapp_row.get("asset_id"))
                        or _clean(service_row.get("asset_id")),
                    ),
                    "",
                ),
                service_id=service_id_map.get(
                    (snapshot.run_id, _clean(row.get("service_id")) or _clean(webapp_row.get("service_id"))),
                    "",
                ),
                webapp_id=webapp_id_map.get(
                    (snapshot.run_id, _clean(row.get("webapp_id")) or _clean(row.get("entity_id"))),
                    "",
                ),
            )
            technology_rows[signature] = (
                _merge_inventory_row(technology_rows[signature], aggregate_row)
                if signature in technology_rows
                else aggregate_row
            )

        _merge_generic_rows(finding_rows, snapshot.findings, key_fields=("finding_id", "fingerprint", "title"))
        _merge_generic_rows(screenshot_rows, snapshot.screenshots, key_fields=("path",))
        _merge_generic_rows(bundle_rows, snapshot.evidence_bundles, key_fields=("bundle_id", "entity_id", "label"))
        _merge_generic_rows(
            relationship_rows,
            snapshot.relationships,
            key_fields=("relationship_id", "target_entity_id", "source_entity_id"),
        )
        _merge_generic_rows(
            tool_execution_rows,
            snapshot.tool_executions,
            key_fields=("execution_id", "tool_name", "command"),
        )

    return RunSnapshot(
        run_id=f"workspace-assets::{canonical_workspace_id or 'ad-hoc'}",
        scan_name="Project Asset Inventory",
        run_dir="",
        state="completed",
        elapsed_seconds=0.0,
        eta_seconds=0.0,
        current_task="Compiled inventory",
        total_tasks=0,
        completed_tasks=0,
        workspace_id=canonical_workspace_id,
        workspace_name=canonical_workspace_name,
        scope=sorted(
            scope_rows.values(),
            key=lambda item: (_lower(item.get("target_type")), _lower(item.get("raw")), _lower(item.get("value"))),
        ),
        assets=sorted(
            asset_rows.values(),
            key=lambda item: (_lower(item.get("kind")), _lower(item.get("name")), _clean(item.get("ip"))),
        ),
        services=sorted(
            service_rows.values(),
            key=lambda item: (_clean(item.get("asset_id")), _safe_int(item.get("port")), _lower(item.get("protocol"))),
        ),
        web_apps=sorted(web_app_rows.values(), key=lambda item: _normalize_url(item.get("url"))),
        technologies=sorted(
            technology_rows.values(),
            key=lambda item: (_lower(item.get("name")), _lower(item.get("version")), _lower(item.get("category"))),
        ),
        tls_assets=sorted(
            tls_rows.values(),
            key=lambda item: (_lower(item.get("host")), _safe_int(item.get("port")), _lower(item.get("protocol"))),
        ),
        site_map=sorted(site_map_rows.values(), key=lambda item: (_lower(item.get("source")), _normalize_url(item.get("url")))),
        endpoints=sorted(
            endpoint_rows.values(),
            key=lambda item: (_normalize_url(item.get("url")), _clean(item.get("method")).upper(), _lower(item.get("kind"))),
        ),
        parameters=sorted(
            parameter_rows.values(),
            key=lambda item: (_lower(item.get("name")), _lower(item.get("location")), _clean(item.get("endpoint_id"))),
        ),
        forms=sorted(
            form_rows.values(),
            key=lambda item: (_normalize_url(item.get("action_url")), _clean(item.get("method")).upper()),
        ),
        login_surfaces=sorted(login_surface_rows.values(), key=lambda item: _normalize_url(item.get("url"))),
        findings=sorted(
            finding_rows.values(),
            key=lambda item: (_lower(item.get("severity")), _lower(item.get("title")), _lower(item.get("finding_id"))),
        ),
        screenshots=sorted(screenshot_rows.values(), key=lambda item: _lower(item.get("path"))),
        evidence_bundles=sorted(
            bundle_rows.values(),
            key=lambda item: (_lower(item.get("entity_type")), _lower(item.get("entity_id")), _lower(item.get("label"))),
        ),
        relationships=sorted(
            relationship_rows.values(),
            key=lambda item: (
                _lower(item.get("relationship_type")),
                _lower(item.get("source_entity_type")),
                _lower(item.get("source_entity_id")),
                _lower(item.get("target_entity_id")),
            ),
        ),
        tool_executions=sorted(
            tool_execution_rows.values(),
            key=lambda item: (_lower(item.get("tool_name")), _lower(item.get("started_at")), _lower(item.get("execution_id"))),
        ),
    )
