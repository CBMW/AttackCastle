from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse, urlsplit

from attackcastle.core.enums import TargetType
from attackcastle.core.models import RunData
from attackcastle.scope.expansion import is_ip_literal

HTTP_LIKE_PORTS = {80, 443, 8000, 8080, 8443}
TLS_LIKE_PORTS = {443, 465, 587, 993, 995, 8443}
COMMON_WEB_PROMOTION_PORTS = (443, 80, 8443, 8080)


def _normalize_hostname(value: str | None) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    return host if host and not is_ip_literal(host) else ""


def _normalize_url(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower()
    if not parsed.scheme or not host:
        return raw
    netloc = host
    if parsed.port is not None:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    return f"{parsed.scheme.lower()}://{netloc}{path}" + (f"?{parsed.query}" if parsed.query else "")


def _asset_lookup(run_data: RunData) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for asset in run_data.assets:
        if asset.ip:
            lookup[asset.asset_id] = asset.ip
        else:
            lookup[asset.asset_id] = asset.name
    return lookup


def _asset_graph(run_data: RunData) -> tuple[dict[str, Any], dict[str, list[Any]]]:
    asset_by_id = {asset.asset_id: asset for asset in run_data.assets}
    children_by_parent: dict[str, list[Any]] = defaultdict(list)
    for asset in run_data.assets:
        parent_asset_id = str(asset.parent_asset_id or "").strip()
        if parent_asset_id:
            children_by_parent[parent_asset_id].append(asset)
    return asset_by_id, children_by_parent


def _service_hostnames(run_data: RunData, asset_id: str) -> list[str]:
    asset_by_id, children_by_parent = _asset_graph(run_data)
    hostnames: list[str] = []
    seen: set[str] = set()

    def _append(value: str | None) -> None:
        normalized = _normalize_hostname(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            hostnames.append(normalized)

    asset = asset_by_id.get(asset_id)
    if asset is not None:
        _append(asset.name)
        for alias in getattr(asset, "aliases", []):
            _append(alias)
        parent_asset_id = str(asset.parent_asset_id or "").strip()
        if parent_asset_id:
            parent = asset_by_id.get(parent_asset_id)
            if parent is not None:
                _append(parent.name)
                for alias in getattr(parent, "aliases", []):
                    _append(alias)
        for child in children_by_parent.get(asset.asset_id, []):
            _append(child.name)
            for alias in getattr(child, "aliases", []):
                _append(alias)
    return hostnames


def _candidate_web_hosts(run_data: RunData) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()

    def _append(value: str | None) -> None:
        normalized = _normalize_hostname(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            hosts.append(normalized)

    for scope_target in run_data.scope:
        if scope_target.target_type in {
            TargetType.DOMAIN,
            TargetType.WILDCARD_DOMAIN,
            TargetType.URL,
            TargetType.HOST_PORT,
        }:
            _append(scope_target.host or scope_target.value)
            for alias in scope_target.aliases:
                _append(alias)

    for asset in run_data.assets:
        if asset.kind in {"domain", "scope_target"} or not asset.ip:
            _append(asset.name)
            for alias in getattr(asset, "aliases", []):
                _append(alias)

    discovered_hosts = run_data.facts.get("subdomain_enum.discovered_hosts", [])
    if isinstance(discovered_hosts, list):
        for host in discovered_hosts:
            _append(str(host or ""))

    return hosts


def _add_target(
    targets: list[dict[str, str | int]],
    seen: set[str],
    *,
    url: str,
    asset_id: str = "",
    service_id: str = "",
    webapp_id: str = "",
    candidate_source: str = "",
) -> None:
    normalized_url = _normalize_url(url)
    if not normalized_url or normalized_url in seen:
        return
    seen.add(normalized_url)
    row: dict[str, str | int] = {
        "url": normalized_url,
        "asset_id": asset_id,
        "service_id": service_id,
    }
    if webapp_id:
        row["webapp_id"] = webapp_id
    if candidate_source:
        row["candidate_source"] = candidate_source
    targets.append(row)


def collect_web_targets(run_data: RunData) -> list[dict[str, str | int]]:
    targets: list[dict[str, str | int]] = []
    seen: set[str] = set()

    for scope_target in run_data.scope:
        if scope_target.target_type == TargetType.URL:
            _add_target(
                targets,
                seen,
                url=scope_target.value,
                asset_id=scope_target.target_id,
                candidate_source="scope_url",
            )
        elif (
            scope_target.target_type == TargetType.HOST_PORT
            and scope_target.host
            and scope_target.port in HTTP_LIKE_PORTS
        ):
            scheme = "https" if scope_target.port in {443, 8443} else "http"
            if (scheme == "http" and scope_target.port == 80) or (
                scheme == "https" and scope_target.port == 443
            ):
                url = f"{scheme}://{scope_target.host}"
            else:
                url = f"{scheme}://{scope_target.host}:{scope_target.port}"
            _add_target(
                targets,
                seen,
                url=url,
                asset_id=scope_target.target_id,
                candidate_source="scope_host_port",
            )

    for service in run_data.services:
        name = (service.name or "").lower()
        if service.port in HTTP_LIKE_PORTS or "http" in name:
            scheme = "https" if service.port in {443, 8443} or "https" in name else "http"
            service_hosts = _service_hostnames(run_data, service.asset_id)
            fallback_host = _asset_lookup(run_data).get(service.asset_id)
            if fallback_host and not service_hosts:
                service_hosts = [fallback_host]
            for host in service_hosts:
                if (scheme == "http" and service.port == 80) or (
                    scheme == "https" and service.port == 443
                ):
                    url = f"{scheme}://{host}"
                else:
                    url = f"{scheme}://{host}:{service.port}"
                _add_target(
                    targets,
                    seen,
                    url=url,
                    asset_id=service.asset_id,
                    service_id=service.service_id,
                    candidate_source="service",
                )

    normalized_confirmed_urls = {
        _normalize_url(str(web_app.url or "").strip())
        for web_app in run_data.web_apps
        if str(web_app.url or "").strip()
    }
    for host in _candidate_web_hosts(run_data):
        for port in COMMON_WEB_PROMOTION_PORTS:
            scheme = "https" if port in {443, 8443} else "http"
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                url = f"{scheme}://{host}"
            else:
                url = f"{scheme}://{host}:{port}"
            if _normalize_url(url) in normalized_confirmed_urls:
                continue
            _add_target(
                targets,
                seen,
                url=url,
                candidate_source="host_promotion",
            )

    discovery_candidates = run_data.facts.get("web_discovery.url_candidates", [])
    if isinstance(discovery_candidates, list):
        for candidate in discovery_candidates:
            if not isinstance(candidate, dict):
                continue
            url = str(candidate.get("url", "")).strip()
            if not url:
                continue
            _add_target(
                targets,
                seen,
                url=url,
                asset_id=str(candidate.get("asset_id") or ""),
                service_id=str(candidate.get("service_id") or ""),
                webapp_id=str(candidate.get("webapp_id") or ""),
                candidate_source="web_discovery",
            )

    discovered_urls = run_data.facts.get("web_discovery.discovered_urls", [])
    if isinstance(discovered_urls, list):
        for url_value in discovered_urls:
            url = str(url_value).strip()
            if not url:
                continue
            _add_target(
                targets,
                seen,
                url=url,
                candidate_source="web_discovery_list",
            )
    vhost_candidates = run_data.facts.get("vhost_discovery.url_candidates", [])
    if isinstance(vhost_candidates, list):
        for candidate in vhost_candidates:
            if not isinstance(candidate, dict):
                continue
            url = str(candidate.get("url", "")).strip()
            if not url:
                continue
            _add_target(
                targets,
                seen,
                url=url,
                asset_id=str(candidate.get("asset_id") or ""),
                service_id=str(candidate.get("service_id") or ""),
                candidate_source="vhost_discovery",
            )
    return targets


def collect_confirmed_web_targets(run_data: RunData) -> list[dict[str, str | int]]:
    targets: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for web_app in run_data.web_apps:
        _add_target(
            targets,
            seen,
            url=web_app.url,
            asset_id=web_app.asset_id,
            service_id=web_app.service_id or "",
            webapp_id=web_app.webapp_id,
            candidate_source="confirmed_web_app",
        )
    return targets


def collect_tls_targets(run_data: RunData) -> list[dict[str, str | int]]:
    targets: list[dict[str, str | int]] = []
    seen = set()
    assets = _asset_lookup(run_data)

    for service in run_data.services:
        service_name = (service.name or "").lower()
        if service.port in TLS_LIKE_PORTS or "ssl" in service_name or "https" in service_name:
            host = assets.get(service.asset_id)
            if not host:
                continue
            key = (host, service.port)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "host": host,
                    "port": service.port,
                    "asset_id": service.asset_id,
                    "service_id": service.service_id,
                }
            )

    for scope_target in run_data.scope:
        if scope_target.target_type == TargetType.URL and scope_target.host:
            parsed = urlparse(scope_target.value)
            if parsed.scheme.lower() != "https":
                continue
            port = parsed.port or 443
            key = (scope_target.host, port)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "host": scope_target.host,
                    "port": port,
                    "asset_id": scope_target.target_id,
                    "service_id": "",
                }
            )

    return targets


def collect_wordpress_targets(run_data: RunData) -> list[dict[str, str | int]]:
    targets: list[dict[str, str | int]] = []
    seen = set()

    wordpress_by_webapp: dict[str, dict[str, str | int]] = {}
    web_lookup = {web_app.webapp_id: web_app for web_app in run_data.web_apps}

    for observation in run_data.observations:
        if observation.entity_type != "web_app":
            continue
        if observation.key == "tech.wordpress.detected" and observation.value is True:
            web_app = web_lookup.get(observation.entity_id)
            if not web_app:
                continue
            wordpress_by_webapp[web_app.webapp_id] = {
                "url": web_app.url,
                "asset_id": web_app.asset_id,
                "service_id": web_app.service_id or "",
                "webapp_id": web_app.webapp_id,
            }
        if observation.key == "tech.wordpress.version":
            web_app = web_lookup.get(observation.entity_id)
            if not web_app:
                continue
            wordpress_by_webapp[web_app.webapp_id] = {
                "url": web_app.url,
                "asset_id": web_app.asset_id,
                "service_id": web_app.service_id or "",
                "webapp_id": web_app.webapp_id,
            }

    technologies_by_webapp: dict[str, list[str]] = defaultdict(list)
    for technology in run_data.technologies:
        if not technology.webapp_id:
            continue
        technologies_by_webapp[technology.webapp_id].append(technology.name.lower())

    for webapp_id, names in technologies_by_webapp.items():
        if not any("wordpress" in name for name in names):
            continue
        web_app = web_lookup.get(webapp_id)
        if not web_app:
            continue
        wordpress_by_webapp.setdefault(
            web_app.webapp_id,
            {
                "url": web_app.url,
                "asset_id": web_app.asset_id,
                "service_id": web_app.service_id or "",
                "webapp_id": web_app.webapp_id,
            },
        )

    for target in wordpress_by_webapp.values():
        key = str(target.get("url", ""))
        if not key or key in seen:
            continue
        seen.add(key)
        targets.append(target)
    return targets


def collect_sqlmap_targets(run_data: RunData) -> list[dict[str, str | int]]:
    targets: list[dict[str, str | int]] = []
    seen: set[str] = set()
    forms_detected: set[str] = set()
    important_targets: set[str] = set()
    parameterized: dict[str, set[str]] = defaultdict(set)
    discovery_parameterized: dict[str, set[str]] = defaultdict(set)

    for observation in run_data.observations:
        if observation.entity_type != "web_app":
            continue
        if observation.key == "web.forms.detected" and observation.value is True:
            forms_detected.add(observation.entity_id)
        if observation.key == "web.important_target" and observation.value is True:
            important_targets.add(observation.entity_id)
        if observation.key == "web.input.parameters":
            value = observation.value
            if isinstance(value, list) and value:
                parameterized[observation.entity_id].update(str(item) for item in value if str(item).strip())
        if observation.key == "web.discovery.parameter_candidates":
            value = observation.value
            if isinstance(value, list):
                discovery_parameterized[observation.entity_id].update(
                    str(item) for item in value if str(item).strip()
                )

    risky_tokens = {"id", "user", "uid", "account", "email", "name", "search", "query", "q", "sort", "order", "page", "cat", "category", "item", "product", "filter", "where", "ref", "token"}

    def _score_candidate(
        url: str,
        webapp_id: str,
        forms_count: int,
        has_forms_signal: bool,
    ) -> tuple[int, list[str], list[str]]:
        parsed = urlparse(url)
        query_params = [pair.split("=", 1)[0].strip() for pair in parsed.query.split("&") if pair]
        known_params = sorted(
            {item for item in query_params if item}
            | parameterized.get(webapp_id, set())
            | discovery_parameterized.get(webapp_id, set())
        )
        risky_params = [item for item in known_params if item.lower() in risky_tokens]
        score = 0
        reasons: list[str] = []

        if parsed.query:
            score += 4
            reasons.append("query_string_present")
        if known_params:
            score += min(4, len(known_params))
            reasons.append(f"parameter_count:{len(known_params)}")
        if risky_params:
            score += min(6, len(risky_params) * 2)
            reasons.append(f"risky_parameters:{','.join(risky_params[:5])}")
        if forms_count > 0 or has_forms_signal:
            score += 3
            reasons.append("forms_detected")
        if any(token in parsed.path.lower() for token in ("login", "api", "search", "item", "product", "account")):
            score += 1
            reasons.append("risky_path_pattern")
        if webapp_id in important_targets:
            score += 1
            reasons.append("important_target_signal")
        return score, reasons, known_params

    for web_app in run_data.web_apps:
        parsed = urlparse(web_app.url)
        has_form_signal = web_app.forms_count > 0 or web_app.webapp_id in forms_detected
        has_parameter_signal = bool(parameterized.get(web_app.webapp_id) or discovery_parameterized.get(web_app.webapp_id))
        if not (bool(parsed.query) or has_form_signal or has_parameter_signal):
            continue
        if web_app.url in seen:
            continue
        score, reasons, param_names = _score_candidate(
            url=web_app.url,
            webapp_id=web_app.webapp_id,
            forms_count=int(web_app.forms_count),
            has_forms_signal=has_form_signal,
        )
        seen.add(web_app.url)
        targets.append(
            {
                "url": web_app.url,
                "asset_id": web_app.asset_id,
                "service_id": web_app.service_id or "",
                "webapp_id": web_app.webapp_id,
                "score": score,
                "reasons": reasons,
                "parameters": param_names,
            }
        )

    # Fallback for scope URLs with query parameters.
    for scope_target in run_data.scope:
        if scope_target.target_type != TargetType.URL:
            continue
        parsed = urlparse(scope_target.value)
        if not parsed.query:
            continue
        if scope_target.value in seen:
            continue
        seen.add(scope_target.value)
        query_params = [pair.split("=", 1)[0].strip() for pair in parsed.query.split("&") if pair]
        risky_params = [item for item in query_params if item.lower() in risky_tokens]
        score = 4 + min(4, len(query_params)) + min(6, len(risky_params) * 2)
        reasons = ["query_string_present"]
        if query_params:
            reasons.append(f"parameter_count:{len(query_params)}")
        if risky_params:
            reasons.append(f"risky_parameters:{','.join(risky_params[:5])}")
        targets.append(
            {
                "url": scope_target.value,
                "asset_id": scope_target.target_id,
                "service_id": "",
                "webapp_id": "",
                "score": score,
                "reasons": reasons,
                "parameters": query_params,
            }
        )
    targets.sort(key=lambda item: (-int(item.get("score", 0)), str(item.get("url", ""))))
    return targets
