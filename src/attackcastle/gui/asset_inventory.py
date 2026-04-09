from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

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
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            parts.path or "/",
            parts.query,
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


def _asset_signature_for_row(
    row: dict[str, Any],
    assets_by_id: dict[str, dict[str, Any]],
    *,
    visited: set[str] | None = None,
) -> str:
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
