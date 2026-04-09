from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from hashlib import sha1
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from attackcastle.adapters.base import build_tool_execution
from attackcastle.adapters.web_discovery.parser import (
    detect_frontend_libraries,
    extract_discovery_urls,
    extract_framework_artifact_urls,
    extract_graphql_endpoints,
    extract_js_endpoints,
    extract_query_param_names,
    extract_script_urls,
    extract_source_map_urls,
    extract_structured_endpoints,
)
from attackcastle.core.interfaces import AdapterContext, AdapterResult
from attackcastle.core.models import Evidence, Observation, RunData, Technology, WebApplication, new_id, now_utc
from attackcastle.core.runtime_events import emit_artifact_event, emit_entity_event, emit_runtime_event
from attackcastle.normalization.correlator import collect_web_targets
from attackcastle.proxy import open_url

BLOCKING_STATUS_CODES = {403, 406, 429, 503}
SEED_DISCOVERY_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/api-docs",
    "/graphql",
    "/actuator",
    "/actuator/health",
]


def _safe_name(value: str) -> str:
    return sha1(value.encode("utf-8")).hexdigest()[:12]  # noqa: S324


def _load_wordlist(path_value: str, limit: int, *, prefix_slash: bool = False) -> list[str]:
    path_text = str(path_value or "").strip()
    if not path_text:
        return []
    path = Path(path_text).expanduser()
    if not path.exists() or not path.is_file():
        return []
    values: list[str] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if prefix_slash:
            value = "/" + value.lstrip("/")
        if value in seen:
            continue
        seen.add(value)
        values.append(value)
        if len(values) >= limit:
            break
    return values


def _build_query_variant(url: str, parameter_name: str, parameter_value: str) -> str:
    parsed = urlsplit(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    if any(name == parameter_name for name, _ in existing):
        return url
    query = urlencode([*existing, (parameter_name, parameter_value)], doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _is_outdated_library(name: str, version: str | None) -> bool:
    normalized = str(name or "").strip().lower()
    parsed_version = str(version or "").strip()
    if not parsed_version:
        return normalized in {"angularjs"}
    numbers = [int(part) for part in parsed_version.split(".") if part.isdigit()]
    if normalized == "jquery":
        return bool(numbers) and numbers[:2] < [3, 5]
    if normalized == "bootstrap":
        return bool(numbers) and numbers[:2] < [4, 6]
    if normalized == "angularjs":
        return True
    return False


class WebDiscoveryAdapter:
    name = "web_discovery"
    capability = "web_discovery"
    noise_score = 5
    cost_score = 5

    def preview_commands(self, context: AdapterContext, run_data: RunData) -> list[str]:
        return [f"crawl {item['url']}" for item in collect_web_targets(run_data)[:25]]

    def _ensure_web_entity(
        self,
        run_data: RunData,
        result: AdapterResult,
        target: dict[str, str | int],
    ) -> str:
        existing_id = str(target.get("webapp_id") or "").strip()
        if existing_id:
            return existing_id
        url = str(target["url"])
        for item in run_data.web_apps:
            if item.url == url:
                return item.webapp_id
        for item in result.web_apps:
            if item.url == url:
                return item.webapp_id
        web_app = WebApplication(
            webapp_id=new_id("web"),
            asset_id=str(target.get("asset_id") or ""),
            service_id=str(target.get("service_id") or "") or None,
            url=url,
            source_tool=self.name,
            parser_version="web_discovery_v2",
        )
        result.web_apps.append(web_app)
        return web_app.webapp_id

    def _fetch_document(
        self,
        url: str,
        timeout_seconds: int,
        user_agent: str,
        body_limit_bytes: int,
        proxy_url: str | None = None,
    ) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"User-Agent": user_agent})
        ssl_context = ssl._create_unverified_context()
        try:
            with open_url(  # noqa: S310
                request,
                timeout=timeout_seconds,
                proxy_url=proxy_url,
                https_context=ssl_context if url.startswith("https://") else None,
            ) as response:
                payload = response.read(max(1024, body_limit_bytes))
                return {
                    "status_code": response.getcode(),
                    "headers": {key.lower(): value for key, value in response.headers.items()},
                    "body_text": payload.decode("utf-8", errors="ignore"),
                    "final_url": response.geturl() or url,
                    "error": None,
                }
        except urllib.error.HTTPError as exc:
            payload = exc.read(max(1024, body_limit_bytes))
            return {
                "status_code": exc.code,
                "headers": {key.lower(): value for key, value in exc.headers.items()},
                "body_text": payload.decode("utf-8", errors="ignore"),
                "final_url": exc.geturl() or url,
                "error": f"http_error:{exc.code}",
            }

    def _mode_adjusted_limits(
        self,
        probe_mode: str,
        crawl_limit: int,
        careful_crawl_limit: int,
        max_script_fetches: int,
    ) -> tuple[int, int]:
        if probe_mode == "careful":
            return max(6, min(crawl_limit, careful_crawl_limit)), max(1, min(max_script_fetches, 2))
        if probe_mode == "balanced":
            return max(10, min(crawl_limit, max(careful_crawl_limit + 4, int(crawl_limit * 0.7)))), max(
                2,
                min(max_script_fetches, 4),
            )
        return crawl_limit, max_script_fetches

    def _append_coverage_gap(
        self,
        gaps: list[dict[str, Any]],
        url: str,
        probe_mode: str,
        reason: str,
        impact: str,
        suggested_action: str,
        status_code: int | None = None,
    ) -> None:
        gap = {
            "url": url,
            "mode": probe_mode,
            "reason": reason,
            "impact": impact,
            "suggested_action": suggested_action,
        }
        if status_code is not None:
            gap["status_code"] = status_code
        if gap not in gaps:
            gaps.append(gap)

    def run(self, context: AdapterContext, run_data: RunData) -> AdapterResult:
        started_at = now_utc()
        result = AdapterResult()
        execution_id = new_id("exec")
        config = context.config.get("web_discovery", {})
        timeout_seconds = int(config.get("timeout_seconds", 10))
        user_agent = context.config.get("scan", {}).get(
            "user_agent", "AttackCastle/0.1 (+authorized-security-assessment)"
        )
        crawl_limit = int(config.get("crawl_limit", 40))
        careful_crawl_limit = int(config.get("careful_crawl_limit", 12))
        max_new_webapps = int(config.get("max_new_webapps", 200))
        same_host_only = bool(config.get("same_host_only", True))
        max_script_fetches = int(config.get("max_script_fetches", 6))
        max_script_bytes = int(config.get("max_script_bytes", 512 * 1024))
        endpoint_wordlist = _load_wordlist(
            str(config.get("endpoint_wordlist_path", "")),
            int(config.get("endpoint_wordlist_limit", 120)),
            prefix_slash=True,
        )
        parameter_wordlist = _load_wordlist(
            str(config.get("parameter_wordlist_path", "")),
            int(config.get("parameter_wordlist_limit", 32)),
        )
        payload_wordlist = _load_wordlist(
            str(config.get("payload_wordlist_path", "")),
            int(config.get("payload_wordlist_limit", 4)),
        )
        synthesized_url_limit = int(config.get("synthesized_url_limit", 80))
        default_fuzz_value = str(config.get("default_fuzz_value", "1"))
        limiter = getattr(context, "rate_limiter", None)
        proxy_url = str(context.config.get("proxy", {}).get("url", "") or "").strip()

        existing_scanned = set(run_data.facts.get("web_discovery.scanned_urls", []))
        discovered_url_targets: list[dict[str, str]] = []
        discovered_urls: list[str] = []
        scanned_urls: list[str] = []
        total_js_endpoints = 0
        total_source_maps = 0
        total_libraries = 0
        coverage_gaps: list[dict[str, Any]] = []

        for target in collect_web_targets(run_data):
            base_url = str(target["url"])
            if base_url in existing_scanned:
                continue
            emit_runtime_event(
                context,
                "task.progress",
                {"adapter": self.name, "phase": "target_started", "url": base_url},
            )
            service_key = ""
            if target.get("service_id"):
                service_key = f"service:{target.get('service_id')}"

            probe_mode = "aggressive"
            if limiter is not None:
                probe_mode = limiter.current_mode(target_key=base_url, service_key=service_key or None)
            effective_crawl_limit, effective_script_limit = self._mode_adjusted_limits(
                probe_mode,
                crawl_limit,
                careful_crawl_limit,
                max_script_fetches,
            )
            web_entity_id = self._ensure_web_entity(run_data, result, target)
            fetched_documents: dict[str, dict[str, Any]] = {}
            warnings: list[str] = []
            per_target_gaps: list[dict[str, Any]] = []

            seed_urls = [
                base_url,
                *[urljoin(base_url, path) for path in [*SEED_DISCOVERY_PATHS, *endpoint_wordlist]],
            ]
            for seed_url in seed_urls:
                if len(fetched_documents) >= effective_crawl_limit:
                    break
                if limiter is not None:
                    limiter.throttle(target_key=seed_url, service_key=service_key or None)
                try:
                    fetch_kwargs = {
                        "timeout_seconds": timeout_seconds,
                        "user_agent": user_agent,
                        "body_limit_bytes": max_script_bytes,
                    }
                    if proxy_url:
                        fetch_kwargs["proxy_url"] = proxy_url
                    document = self._fetch_document(seed_url, **fetch_kwargs)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(str(exc))
                    self._append_coverage_gap(
                        per_target_gaps,
                        seed_url,
                        probe_mode,
                        "fetch failure during discovery",
                        "Discovery coverage reduced for this target.",
                        "Retry manually or reduce WAF pressure with slower browser/Burp interaction.",
                    )
                    if limiter is not None:
                        limiter.record(target_key=seed_url, service_key=service_key or None, success=False)
                    continue
                fetched_documents[seed_url] = document
                status_code = document.get("status_code")
                is_noisy = isinstance(status_code, int) and int(status_code) in BLOCKING_STATUS_CODES
                if limiter is not None:
                    limiter.record(
                        target_key=seed_url,
                        service_key=service_key or None,
                        success=not is_noisy,
                        status_code=int(status_code) if isinstance(status_code, int) else None,
                        noisy_hint=is_noisy,
                    )
                if is_noisy:
                    self._append_coverage_gap(
                        per_target_gaps,
                        seed_url,
                        probe_mode,
                        f"discovery request returned {status_code}",
                        "Paths, JS bundles, and structured endpoints may be incomplete.",
                        "Validate manually in browser/Burp and consider alternate vhost, session, or slower pacing.",
                        status_code=int(status_code),
                    )

            queue = [base_url]
            visited = set(queue)
            while queue and len(fetched_documents) < effective_crawl_limit:
                current = queue.pop(0)
                document = fetched_documents.get(current)
                if document is None:
                    if limiter is not None:
                        limiter.throttle(target_key=current, service_key=service_key or None)
                    try:
                        fetch_kwargs = {
                            "timeout_seconds": timeout_seconds,
                            "user_agent": user_agent,
                            "body_limit_bytes": max_script_bytes,
                        }
                        if proxy_url:
                            fetch_kwargs["proxy_url"] = proxy_url
                        document = self._fetch_document(current, **fetch_kwargs)
                    except Exception:
                        continue
                    fetched_documents[current] = document
                    status_code = document.get("status_code")
                    is_noisy = isinstance(status_code, int) and int(status_code) in BLOCKING_STATUS_CODES
                    if limiter is not None:
                        limiter.record(
                            target_key=current,
                            service_key=service_key or None,
                            success=not is_noisy,
                            status_code=int(status_code) if isinstance(status_code, int) else None,
                            noisy_hint=is_noisy,
                        )
                if document.get("status_code") != 200:
                    continue
                body = str(document.get("body_text") or "")
                new_urls = [
                    *extract_discovery_urls(current, body, same_host_only=same_host_only),
                    *extract_structured_endpoints(current, body, same_host_only=same_host_only),
                ]
                for item in new_urls:
                    if item in visited:
                        continue
                    visited.add(item)
                    queue.append(item)

            per_target_discovered: list[str] = []
            js_endpoints: list[str] = []
            parameter_names: list[str] = []
            source_maps: list[str] = []
            graphql_endpoints: list[str] = []
            framework_artifacts: list[str] = []
            script_urls: list[str] = []
            libraries: list[dict[str, Any]] = []

            for page_url, document in fetched_documents.items():
                if document.get("status_code") != 200:
                    continue
                if page_url != base_url and page_url not in per_target_discovered:
                    per_target_discovered.append(page_url)
                body_text = str(document.get("body_text") or "")
                page_urls = [
                    *extract_discovery_urls(page_url, body_text, same_host_only=same_host_only),
                    *extract_structured_endpoints(page_url, body_text, same_host_only=same_host_only),
                ]
                for item in page_urls:
                    if item not in per_target_discovered:
                        per_target_discovered.append(item)
                page_js = extract_js_endpoints(page_url, body_text, same_host_only=same_host_only)
                for item in page_js:
                    if item not in js_endpoints:
                        js_endpoints.append(item)
                page_graphql = extract_graphql_endpoints(page_url, body_text, same_host_only=same_host_only)
                for item in page_graphql:
                    if item not in graphql_endpoints:
                        graphql_endpoints.append(item)
                page_framework = extract_framework_artifact_urls(page_url, body_text, same_host_only=same_host_only)
                for item in page_framework:
                    if item not in framework_artifacts:
                        framework_artifacts.append(item)
                page_scripts = extract_script_urls(page_url, body_text, same_host_only=same_host_only)
                for item in page_scripts:
                    if item not in script_urls:
                        script_urls.append(item)
                for candidate in [page_url, *page_urls, *page_js, *page_graphql, *page_framework]:
                    for param in extract_query_param_names(candidate):
                        if param not in parameter_names:
                            parameter_names.append(param)
                for detection in detect_frontend_libraries(body_text):
                    if detection not in libraries:
                        libraries.append(detection)

            fetched_scripts = 0
            for script_url in script_urls:
                if fetched_scripts >= effective_script_limit:
                    break
                if limiter is not None:
                    limiter.throttle(target_key=script_url, service_key=service_key or None)
                try:
                    fetch_kwargs = {
                        "timeout_seconds": timeout_seconds,
                        "user_agent": user_agent,
                        "body_limit_bytes": max_script_bytes,
                    }
                    if proxy_url:
                        fetch_kwargs["proxy_url"] = proxy_url
                    script_document = self._fetch_document(script_url, **fetch_kwargs)
                except Exception as exc:  # noqa: BLE001
                    warnings.append(str(exc))
                    continue
                fetched_scripts += 1
                status_code = script_document.get("status_code")
                is_noisy = isinstance(status_code, int) and int(status_code) in BLOCKING_STATUS_CODES
                if limiter is not None:
                    limiter.record(
                        target_key=script_url,
                        service_key=service_key or None,
                        success=not is_noisy,
                        status_code=int(status_code) if isinstance(status_code, int) else None,
                        noisy_hint=is_noisy,
                    )
                if script_document.get("status_code") != 200:
                    continue
                script_body = str(script_document.get("body_text") or "")
                script_endpoints = extract_js_endpoints(script_url, script_body, same_host_only=same_host_only)
                for item in script_endpoints:
                    if item not in js_endpoints:
                        js_endpoints.append(item)
                script_graphql = extract_graphql_endpoints(script_url, script_body, same_host_only=same_host_only)
                for item in script_graphql:
                    if item not in graphql_endpoints:
                        graphql_endpoints.append(item)
                script_framework = extract_framework_artifact_urls(
                    script_url,
                    script_body,
                    same_host_only=same_host_only,
                )
                for item in script_framework:
                    if item not in framework_artifacts:
                        framework_artifacts.append(item)
                script_source_maps = extract_source_map_urls(script_url, script_body, same_host_only=same_host_only)
                for item in script_source_maps:
                    if item not in source_maps:
                        source_maps.append(item)
                for detection in detect_frontend_libraries(script_body):
                    if detection not in libraries:
                        libraries.append(detection)
                for candidate in [*script_endpoints, *script_graphql, *script_framework, *script_source_maps]:
                    for param in extract_query_param_names(candidate):
                        if param not in parameter_names:
                            parameter_names.append(param)

            for parameter_name in parameter_wordlist:
                if parameter_name not in parameter_names:
                    parameter_names.append(parameter_name)

            synthesized_urls: list[str] = []
            query_values = payload_wordlist or [default_fuzz_value]
            for source_url in [base_url, *per_target_discovered]:
                if len(synthesized_urls) >= synthesized_url_limit:
                    break
                for parameter_name in parameter_names:
                    for query_value in query_values:
                        candidate_url = _build_query_variant(source_url, parameter_name, query_value)
                        if candidate_url == source_url or candidate_url in synthesized_urls:
                            continue
                        synthesized_urls.append(candidate_url)
                        if len(synthesized_urls) >= synthesized_url_limit:
                            break
                    if len(synthesized_urls) >= synthesized_url_limit:
                        break

            total_js_endpoints += len(js_endpoints)
            total_source_maps += len(source_maps)
            total_libraries += len(libraries)
            coverage_gaps.extend(per_target_gaps)

            artifact_path = context.run_store.artifact_path(
                self.name,
                f"discovery_{_safe_name(base_url)}.json",
            )
            artifact_payload = {
                "base_url": base_url,
                "web_entity_id": web_entity_id,
                "probe_mode": probe_mode,
                "fetched_count": len(fetched_documents),
                "urls": per_target_discovered,
                "js_endpoints": js_endpoints,
                "graphql_endpoints": graphql_endpoints,
                "framework_artifacts": framework_artifacts,
                "source_maps": source_maps,
                "script_urls": script_urls[:effective_script_limit],
                "libraries": libraries,
                "parameters": parameter_names,
                "wordlist_endpoints": endpoint_wordlist,
                "wordlist_parameters": parameter_wordlist,
                "wordlist_payloads": payload_wordlist,
                "wordlist_url_candidates": synthesized_urls,
                "warnings": warnings,
                "coverage_gaps": per_target_gaps,
            }
            artifact_path.write_text(json.dumps(artifact_payload, indent=2), encoding="utf-8")
            evidence = Evidence(
                evidence_id=new_id("evidence"),
                source_tool=self.name,
                kind="web_discovery",
                snippet=(
                    f"discovered {len(per_target_discovered)} urls, {len(js_endpoints)} JS endpoints, "
                    f"{len(libraries)} libraries from {base_url}"
                )[:380],
                artifact_path=str(artifact_path),
                selector={"kind": "target", "url": base_url},
                source_execution_id=execution_id,
                parser_version="web_discovery_v2",
                confidence=0.85,
            )
            result.evidence.append(evidence)
            emit_entity_event(context, "evidence", evidence, source=self.name)
            emit_artifact_event(
                context,
                artifact_path=artifact_path,
                kind="web_discovery",
                source_tool=self.name,
                caption=f"Discovery data for {base_url}",
            )
            emit_runtime_event(
                context,
                "site_map.updated",
                {
                    "base_url": base_url,
                    "webapp_id": web_entity_id,
                    "urls": per_target_discovered[:500],
                    "js_endpoints": js_endpoints[:200],
                    "graphql_endpoints": graphql_endpoints[:100],
                    "source_maps": source_maps[:100],
                    "parameters": parameter_names[:200],
                    "wordlist_url_candidates": synthesized_urls[:200],
                },
            )

            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.discovery.urls",
                    value=per_target_discovered,
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.82,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="web_discovery_v2",
                )
            )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.discovery.js_endpoints",
                    value=js_endpoints,
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.8,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="web_discovery_v2",
                )
            )
            result.observations.append(
                Observation(
                    observation_id=new_id("obs"),
                    key="web.execution.mode",
                    value=probe_mode,
                    entity_type="web_app",
                    entity_id=web_entity_id,
                    source_tool=self.name,
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                    source_execution_id=execution_id,
                    parser_version="web_discovery_v2",
                )
            )
            if probe_mode != "aggressive":
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.execution.downgraded",
                        value=True,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.86,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
            if parameter_names:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.discovery.parameter_candidates",
                        value=parameter_names,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
            if source_maps:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.discovery.source_maps",
                        value=source_maps,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.85,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
            if graphql_endpoints:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.discovery.graphql_endpoints",
                        value=graphql_endpoints,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.83,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
            if framework_artifacts:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.discovery.framework_artifacts",
                        value=framework_artifacts,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.82,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
            for gap in per_target_gaps:
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="coverage.gap",
                        value=gap,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.76,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
            if libraries:
                outdated_libraries = [
                    {
                        "name": str(detection.get("name") or ""),
                        "version": str(detection.get("version") or ""),
                    }
                    for detection in libraries
                    if _is_outdated_library(
                        str(detection.get("name") or ""),
                        str(detection.get("version") or "") if detection.get("version") else None,
                    )
                ]
                result.observations.append(
                    Observation(
                        observation_id=new_id("obs"),
                        key="web.discovery.libraries",
                        value=libraries,
                        entity_type="web_app",
                        entity_id=web_entity_id,
                        source_tool=self.name,
                        confidence=0.8,
                        evidence_ids=[evidence.evidence_id],
                        source_execution_id=execution_id,
                        parser_version="web_discovery_v2",
                    )
                )
                if outdated_libraries:
                    result.observations.append(
                        Observation(
                            observation_id=new_id("obs"),
                            key="web.outdated_library",
                            value=outdated_libraries,
                            entity_type="web_app",
                            entity_id=web_entity_id,
                            source_tool=self.name,
                            confidence=0.74,
                            evidence_ids=[evidence.evidence_id],
                            source_execution_id=execution_id,
                            parser_version="web_discovery_v2",
                        )
                    )
                for detection in libraries:
                    result.technologies.append(
                        Technology(
                            tech_id=new_id("tech"),
                            asset_id=str(target.get("asset_id") or ""),
                            webapp_id=web_entity_id,
                            name=str(detection.get("name") or "Frontend Library"),
                            version=str(detection.get("version")) if detection.get("version") else None,
                            confidence=float(detection.get("confidence") or 0.75),
                            source_tool=self.name,
                            source_execution_id=execution_id,
                            parser_version="web_discovery_v2",
                        )
                    )
                    emit_entity_event(context, "technology", result.technologies[-1], source=self.name)

            for discovered_url in [
                *per_target_discovered,
                *js_endpoints,
                *graphql_endpoints,
                *framework_artifacts,
                *source_maps,
                *synthesized_urls,
            ]:
                if discovered_url not in discovered_urls:
                    discovered_urls.append(discovered_url)
                discovered_url_targets.append(
                    {
                        "url": discovered_url,
                        "asset_id": str(target.get("asset_id") or ""),
                        "service_id": str(target.get("service_id") or ""),
                        "webapp_id": web_entity_id,
                    }
                )
            scanned_urls.append(base_url)
            emit_runtime_event(
                context,
                "task.progress",
                {
                    "adapter": self.name,
                    "phase": "target_completed",
                    "url": base_url,
                    "discovered_urls": len(per_target_discovered),
                    "libraries": len(libraries),
                },
            )

        generated_webapps = 0
        existing_web_urls = {item.url for item in run_data.web_apps}
        for item in discovered_url_targets:
            if generated_webapps >= max_new_webapps:
                break
            url = str(item.get("url", "")).strip()
            if not url or url in existing_web_urls:
                continue
            existing_web_urls.add(url)
            generated_webapps += 1
            result.web_apps.append(
                WebApplication(
                    webapp_id=new_id("web"),
                    asset_id=str(item.get("asset_id") or ""),
                    service_id=str(item.get("service_id") or "") or None,
                    url=url,
                    source_tool=self.name,
                    parser_version="web_discovery_v2",
                )
            )
            emit_entity_event(context, "web_app", result.web_apps[-1], source=self.name)

        ended_at = now_utc()
        result.facts["web_discovery.scanned_urls"] = sorted(existing_scanned.union(scanned_urls))
        result.facts["web_discovery.discovered_urls"] = discovered_urls[:3000]
        result.facts["web_discovery.url_candidates"] = discovered_url_targets[:4000]
        result.facts["web_discovery.total_js_endpoints"] = total_js_endpoints
        result.facts["web_discovery.total_source_maps"] = total_source_maps
        result.facts["web_discovery.total_libraries"] = total_libraries
        result.facts["web_discovery.generated_webapps"] = generated_webapps
        result.facts["web_discovery.coverage_gaps"] = coverage_gaps[:500]
        result.facts["web_discovery.wordlist_endpoint_count"] = len(endpoint_wordlist)
        result.facts["web_discovery.wordlist_parameter_count"] = len(parameter_wordlist)
        result.facts["web_discovery.wordlist_payload_count"] = len(payload_wordlist)
        result.tool_executions.append(
            build_tool_execution(
                tool_name=self.name,
                command="python urllib crawl + JS/source map/library discovery",
                started_at=started_at,
                ended_at=ended_at,
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
                "scanned_targets": len(scanned_urls),
                "discovered_urls": len(discovered_urls),
                "generated_webapps": generated_webapps,
                "libraries": total_libraries,
                "source_maps": total_source_maps,
            },
        )
        return result
