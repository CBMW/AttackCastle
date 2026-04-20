from __future__ import annotations

import json
import socket
import ssl
from hashlib import sha1
from typing import Any
from urllib.parse import urlparse

from attackcastle.adapters.base import build_tool_execution, cancellation_requested, current_worker_budget, ordered_parallel_map
from attackcastle.adapters.web_probe.parser import extract_title
from attackcastle.core.enums import TargetType
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, WebApplication, new_id, now_utc
from attackcastle.scope.domains import registrable_domain


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _is_ip_literal(value: str) -> bool:
    try:
        socket.inet_aton(value)
    except OSError:
        return False
    return True


def _root_response_signature(status_code: int | None, title: str | None, body_text: str) -> str:
    normalized_title = (title or "").strip().lower()
    normalized_body = " ".join(body_text.lower().split())[:220]
    return f"{status_code}|{normalized_title}|{normalized_body}"


def _service_base_urls(run_data: RunData) -> list[dict[str, Any]]:
    asset_lookup = {asset.asset_id: asset for asset in run_data.assets}
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for service in run_data.services:
        asset = asset_lookup.get(service.asset_id)
        if not asset or not asset.ip:
            continue
        name = (service.name or "").lower()
        if service.port not in {80, 443, 8080, 8443} and "http" not in name:
            continue
        scheme = "https" if service.port in {443, 8443} or "https" in name else "http"
        key = f"{asset.asset_id}|{service.service_id}|{scheme}|{service.port}"
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "asset_id": asset.asset_id,
                "service_id": service.service_id,
                "host_ip": asset.ip,
                "scheme": scheme,
                "port": int(service.port),
            }
        )
    return rows


def _candidate_hosts_for_asset(run_data: RunData, asset_id: str, service_id: str | None = None) -> list[str]:
    candidates: set[str] = set()
    asset_lookup = {asset.asset_id: asset for asset in run_data.assets}
    asset = asset_lookup.get(asset_id)
    target_ip = asset.ip if asset else None

    for scope_target in run_data.scope:
        if scope_target.target_type in {TargetType.DOMAIN, TargetType.WILDCARD_DOMAIN, TargetType.URL, TargetType.HOST_PORT}:
            host = (scope_target.host or "").strip().lower()
            if host and not _is_ip_literal(host):
                candidates.add(host)

    discovered_hosts = run_data.facts.get("subdomain_enum.discovered_hosts", [])
    if isinstance(discovered_hosts, list):
        for host in discovered_hosts:
            normalized = str(host).strip().lower()
            if normalized and not _is_ip_literal(normalized):
                candidates.add(normalized)

    for candidate_asset in run_data.assets:
        if candidate_asset.asset_id == asset_id:
            continue
        name = (candidate_asset.name or "").strip().lower()
        if not name or _is_ip_literal(name):
            continue
        if candidate_asset.parent_asset_id == asset_id:
            candidates.add(name)
            continue
        if target_ip and candidate_asset.parent_asset_id:
            parent = asset_lookup.get(candidate_asset.parent_asset_id)
            if parent and parent.ip == target_ip:
                candidates.add(name)

    for tls_item in run_data.tls_assets:
        if tls_item.asset_id != asset_id and (service_id is None or tls_item.service_id != service_id):
            continue
        for san in tls_item.sans:
            normalized = str(san).strip().lower()
            if normalized and not _is_ip_literal(normalized):
                candidates.add(normalized)

    for observation in run_data.observations:
        if observation.key != "web.redirect.chain" or not isinstance(observation.value, list):
            continue
        related_web = next((item for item in run_data.web_apps if item.webapp_id == observation.entity_id), None)
        if not related_web:
            continue
        if related_web.asset_id != asset_id and (service_id is None or related_web.service_id != service_id):
            continue
        for item in observation.value:
            if not isinstance(item, dict):
                continue
            for key in ("from", "to"):
                host = (urlparse(str(item.get(key) or "")).hostname or "").strip().lower()
                if host and not _is_ip_literal(host):
                    candidates.add(host)

    root_domains = {root for host in candidates if (root := registrable_domain(host))}
    common_prefixes = (
        "admin",
        "api",
        "app",
        "auth",
        "citrix",
        "dev",
        "gateway",
        "login",
        "mail",
        "mfa",
        "panel",
        "portal",
        "remote",
        "sso",
        "staging",
        "test",
        "vpn",
        "webmail",
    )
    for root_domain in root_domains:
        for prefix in common_prefixes:
            candidates.add(f"{prefix}.{root_domain}")

    return sorted(candidates)


def _raw_request(
    *,
    ip_address: str,
    scheme: str,
    port: int,
    host_header: str,
    timeout_seconds: int,
    response_capture_bytes: int,
    user_agent: str,
) -> dict[str, Any]:
    request_bytes = (
        f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {user_agent}\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    raw = b""
    with socket.create_connection((ip_address, port), timeout=timeout_seconds) as sock:
        connection = sock
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(sock, server_hostname=host_header)
        connection.sendall(request_bytes)
        while len(raw) < response_capture_bytes:
            chunk = connection.recv(min(4096, response_capture_bytes - len(raw)))
            if not chunk:
                break
            raw += chunk
    head, _, body = raw.partition(b"\r\n\r\n")
    head_text = head.decode("utf-8", errors="ignore")
    body_text = body.decode("utf-8", errors="ignore")
    lines = head_text.splitlines()
    status_code = None
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return {
        "status_code": status_code,
        "headers": headers,
        "body_text": body_text,
        "title": extract_title(body_text),
    }


class VHostDiscoveryAdapter:
    name = "vhost_discovery"
    capability = "vhost_discovery"
    noise_score = 4
    cost_score = 4

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        previews: list[str] = []
        for item in _service_base_urls(run_data)[:10]:
            previews.append(
                f"host-header probe {item['scheme']}://{item['host_ip']}:{item['port']} (candidate virtual hosts)"
            )
        return previews

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        execution_id = new_id("exec")
        config = context.config.get("vhost_discovery", {})
        timeout_seconds = int(config.get("timeout_seconds", 6))
        max_candidates_per_service = int(config.get("max_candidates_per_service", 12))
        response_capture_bytes = int(config.get("response_capture_bytes", 65536))
        user_agent = context.config.get("scan", {}).get(
            "user_agent", "AttackCastle/0.1 (+authorized-security-assessment)"
        )
        limiter = getattr(context, "rate_limiter", None)
        existing_candidates = run_data.facts.get("vhost_discovery.url_candidates", [])
        persisted_candidates: list[dict[str, str]] = list(existing_candidates) if isinstance(existing_candidates, list) else []
        discovered: list[dict[str, Any]] = []
        generated_webapps = 0
        existing_web_urls = {web_app.url for web_app in run_data.web_apps}

        def _scan_service(service_row: dict[str, Any]) -> dict[str, Any]:
            partial = AdapterResult()
            local_candidates: list[dict[str, str]] = []
            local_discovered: list[dict[str, Any]] = []
            local_generated = 0
            asset_id = str(service_row["asset_id"])
            service_id = str(service_row["service_id"])
            ip_address = str(service_row["host_ip"])
            scheme = str(service_row["scheme"])
            port = int(service_row["port"])
            if cancellation_requested(context):
                return {
                    "partial": partial,
                    "candidates": local_candidates,
                    "discovered": local_discovered,
                    "generated": local_generated,
                }
            if limiter is not None:
                limiter.throttle(target_key=f"{ip_address}:{port}", service_key=f"service:{service_id}")
            baseline = _raw_request(
                ip_address=ip_address,
                scheme=scheme,
                port=port,
                host_header=ip_address,
                timeout_seconds=timeout_seconds,
                response_capture_bytes=response_capture_bytes,
                user_agent=user_agent,
            )
            baseline_signature = _root_response_signature(
                baseline.get("status_code"),
                baseline.get("title"),
                str(baseline.get("body_text") or ""),
            )
            for candidate_host in _candidate_hosts_for_asset(run_data, asset_id=asset_id, service_id=service_id)[
                :max_candidates_per_service
            ]:
                if cancellation_requested(context):
                    break
                try:
                    response = _raw_request(
                        ip_address=ip_address,
                        scheme=scheme,
                        port=port,
                        host_header=candidate_host,
                        timeout_seconds=timeout_seconds,
                        response_capture_bytes=response_capture_bytes,
                        user_agent=user_agent,
                    )
                except Exception:
                    continue
                signature = _root_response_signature(
                    response.get("status_code"),
                    response.get("title"),
                    str(response.get("body_text") or ""),
                )
                status_code = response.get("status_code")
                title = response.get("title")
                body_text = str(response.get("body_text") or "")
                if status_code in {301, 302, 303, 307, 308} or signature == baseline_signature or not body_text.strip():
                    continue
                canonical_url = (
                    f"{scheme}://{candidate_host}"
                    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                    else f"{scheme}://{candidate_host}:{port}"
                )
                artifact_path = context.run_store.artifact_path(self.name, f"vhost_{_safe_name(canonical_url)}.json")
                artifact_path.write_text(
                    json.dumps(
                        {
                            "ip_address": ip_address,
                            "host_header": candidate_host,
                            "status_code": status_code,
                            "title": title,
                            "headers": response.get("headers", {}),
                            "baseline_signature": baseline_signature,
                            "candidate_signature": signature,
                            "body": body_text[:5000],
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                evidence = Evidence(
                    evidence_id=new_id("evidence"),
                    source_tool=self.name,
                    kind="vhost_discovery",
                    snippet=f"virtual host candidate {candidate_host} on {ip_address}:{port}",
                    artifact_path=str(artifact_path),
                    selector={"kind": "host_header", "host": candidate_host},
                    source_execution_id=execution_id,
                    parser_version="vhost_discovery_v1",
                    confidence=0.82,
                )
                partial.evidence.append(evidence)
                partial.observations.extend(
                    [
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.vhost.discovered",
                            value={"host": candidate_host, "url": canonical_url, "ip": ip_address},
                            entity_type="service",
                            entity_id=service_id,
                            source_tool=self.name,
                            confidence=0.82,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version="vhost_discovery_v1",
                        ),
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.vhost.title",
                            value=title or "",
                            entity_type="service",
                            entity_id=service_id,
                            source_tool=self.name,
                            confidence=0.8,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version="vhost_discovery_v1",
                        ),
                    ]
                )
                partial.web_apps.append(
                    WebApplication(
                        webapp_id=new_id("web"),
                        asset_id=asset_id,
                        service_id=service_id,
                        url=canonical_url,
                        status_code=status_code if isinstance(status_code, int) else None,
                        title=title,
                        forms_count=0,
                        source_tool=self.name,
                        source_execution_id=execution_id,
                        parser_version="vhost_discovery_v1",
                    )
                )
                local_generated += 1
                local_discovered.append(
                    {
                        "asset_id": asset_id,
                        "service_id": service_id,
                        "ip_address": ip_address,
                        "host": candidate_host,
                        "url": canonical_url,
                        "status_code": status_code,
                        "title": title,
                    }
                )
                local_candidates.append({"url": canonical_url, "asset_id": asset_id, "service_id": service_id})
            return {
                "partial": partial,
                "candidates": local_candidates,
                "discovered": local_discovered,
                "generated": local_generated,
            }

        remaining_services = list(_service_base_urls(run_data))
        while remaining_services:
            if cancellation_requested(context):
                result.warnings.append("vhost discovery cancelled by scheduler before all services were processed")
                break
            worker_count = current_worker_budget(
                context,
                self.capability,
                stage="enumeration",
                pending_count=len(remaining_services),
                ceiling=len(remaining_services),
                fallback=1,
            )
            batch = remaining_services[:worker_count]
            remaining_services = remaining_services[worker_count:]
            for item in ordered_parallel_map(batch, max_workers=worker_count, worker=_scan_service):
                partial = item["partial"]
                for web_app in partial.web_apps:
                    if web_app.url in existing_web_urls:
                        continue
                    result.web_apps.append(web_app)
                    existing_web_urls.add(web_app.url)
                result.evidence.extend(partial.evidence)
                result.observations.extend(partial.observations)
                generated_webapps += int(item["generated"])
                discovered.extend(item["discovered"])
                persisted_candidates.extend(item["candidates"])

        result.facts["vhost_discovery.url_candidates"] = persisted_candidates[:3000]
        result.facts["vhost_discovery.discovered"] = discovered[:500]
        result.facts["vhost_discovery.generated_webapps"] = generated_webapps
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="internal host-header virtual host discovery",
                started_at=started_at,
                ended_at=now_utc(),
                status="completed",
                execution_id=execution_id,
                capability=self.capability,
                exit_code=0,
            )
        )
        context.audit.write(
            "adapter.completed",
            {
                "adapter": self.name,
                "generated_webapps": generated_webapps,
                "discovered_hosts": len(discovered),
            },
        )
        return result
