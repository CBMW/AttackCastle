from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlparse

from attackcastle.adapters.web_probe.parser import extract_script_urls as extract_html_script_urls
from attackcastle.adapters.web_probe.parser import extract_structured_urls

HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
FORM_ACTION_RE = re.compile(r"""<form[^>]*action\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
JS_ENDPOINT_RE = re.compile(
    r"""(?:
        fetch\(\s*["'](?P<fetch>[^"']+)["']|
        axios\.(?:get|post|put|patch|delete)\(\s*["'](?P<axios>[^"']+)["']|
        open\(\s*["'][A-Z]+["']\s*,\s*["'](?P<xhr>[^"']+)["']
    )""",
    re.IGNORECASE | re.VERBOSE,
)
PATH_LITERAL_RE = re.compile(r"""["']((?:/|https?://)[^"' ]*(?:api|graphql|swagger|openapi|actuator|v[0-9]+)[^"' ]*)["']""", re.IGNORECASE)
SOURCE_MAP_RE = re.compile(r"""sourceMappingURL\s*=\s*([^\s*]+)""", re.IGNORECASE)
FRAMEWORK_ARTIFACT_RE = re.compile(
    r"""["']((?:/|https?://)[^"' ]*(?:swagger(?:-ui)?|openapi(?:\.json)?|graphql|actuator(?:/[^"' ]+)?|v2/api-docs|api-docs|_next/data|manifest\.json|health|metrics|prometheus)[^"' ]*)["']""",
    re.IGNORECASE,
)
GRAPHQL_MARKER_RE = re.compile(r"""["']((?:/|https?://)[^"']*graphql[^"']*)["']""", re.IGNORECASE)
LIBRARY_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "React": (
        re.compile(r"react(?:\.production(?:\.min)?|\.development)?\.js(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"react@([0-9]+\.[0-9.]+)", re.IGNORECASE),
    ),
    "Angular": (
        re.compile(r"angular(?:\.min)?\.js(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"""ng-version=['"]([0-9]+\.[0-9.]+)['"]""", re.IGNORECASE),
    ),
    "Vue.js": (
        re.compile(r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"vue@([0-9]+\.[0-9.]+)", re.IGNORECASE),
    ),
    "jQuery": (
        re.compile(r"jquery(?:\.min)?\.js(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"jquery v?([0-9]+\.[0-9.]+)", re.IGNORECASE),
    ),
    "Bootstrap": (
        re.compile(r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"bootstrap v?([0-9]+\.[0-9.]+)", re.IGNORECASE),
    ),
    "Axios": (
        re.compile(r"axios(?:\.min)?\.js(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"axios/?([0-9]+\.[0-9.]+)", re.IGNORECASE),
    ),
    "Lodash": (
        re.compile(r"lodash(?:\.min)?\.js(?:\?v=([0-9.]+))?", re.IGNORECASE),
        re.compile(r"lodash@([0-9]+\.[0-9.]+)", re.IGNORECASE),
    ),
}


def _normalize_url(base_url: str, candidate: str) -> str | None:
    value = (candidate or "").strip()
    if not value:
        return None
    if value.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    absolute = urljoin(base_url, unescape(value))
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return None
    return absolute


def extract_discovery_urls(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    discovered: list[str] = []
    base_host = (urlparse(base_url).hostname or "").lower()
    for regex in (HREF_RE, FORM_ACTION_RE):
        for match in regex.finditer(body_text or ""):
            normalized = _normalize_url(base_url, match.group(1))
            if not normalized:
                continue
            host = (urlparse(normalized).hostname or "").lower()
            if same_host_only and base_host and host and host != base_host:
                continue
            if normalized not in discovered:
                discovered.append(normalized)
    return discovered


def extract_js_endpoints(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    endpoints: list[str] = []
    base_host = (urlparse(base_url).hostname or "").lower()
    for match in JS_ENDPOINT_RE.finditer(body_text or ""):
        candidate = match.group("fetch") or match.group("axios") or match.group("xhr")
        normalized = _normalize_url(base_url, candidate or "")
        if not normalized:
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if same_host_only and base_host and host and host != base_host:
            continue
        if normalized not in endpoints:
            endpoints.append(normalized)
    for match in PATH_LITERAL_RE.finditer(body_text or ""):
        normalized = _normalize_url(base_url, match.group(1))
        if not normalized:
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if same_host_only and base_host and host and host != base_host:
            continue
        if normalized not in endpoints:
            endpoints.append(normalized)
    return endpoints


def extract_query_param_names(url_value: str) -> list[str]:
    parsed = urlparse(url_value)
    params: list[str] = []
    if not parsed.query:
        return params
    for pair in parsed.query.split("&"):
        if not pair:
            continue
        key = pair.split("=", 1)[0].strip()
        if key and key not in params:
            params.append(key)
    return params


def extract_script_urls(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    return extract_html_script_urls(base_url, body_text, same_host_only=same_host_only)


def extract_source_map_urls(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    urls: list[str] = []
    base_host = (urlparse(base_url).hostname or "").lower()
    for match in SOURCE_MAP_RE.finditer(body_text or ""):
        normalized = _normalize_url(base_url, match.group(1))
        if not normalized:
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if same_host_only and base_host and host and host != base_host:
            continue
        if normalized not in urls:
            urls.append(normalized)
    return urls


def extract_framework_artifact_urls(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    urls: list[str] = []
    base_host = (urlparse(base_url).hostname or "").lower()
    for match in FRAMEWORK_ARTIFACT_RE.finditer(body_text or ""):
        normalized = _normalize_url(base_url, match.group(1))
        if not normalized:
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if same_host_only and base_host and host and host != base_host:
            continue
        if normalized not in urls:
            urls.append(normalized)
    return urls


def extract_structured_endpoints(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    return extract_structured_urls(base_url, body_text, same_host_only=same_host_only)


def extract_graphql_endpoints(base_url: str, body_text: str, same_host_only: bool = True) -> list[str]:
    urls: list[str] = []
    base_host = (urlparse(base_url).hostname or "").lower()
    for match in GRAPHQL_MARKER_RE.finditer(body_text or ""):
        normalized = _normalize_url(base_url, match.group(1))
        if not normalized:
            continue
        host = (urlparse(normalized).hostname or "").lower()
        if same_host_only and base_host and host and host != base_host:
            continue
        if normalized not in urls:
            urls.append(normalized)
    return urls


def detect_frontend_libraries(body_text: str) -> list[dict[str, str | None | float]]:
    detections: list[dict[str, str | None | float]] = []
    lowered = (body_text or "").lower()
    for library_name, patterns in LIBRARY_PATTERNS.items():
        version = None
        confidence = 0.68
        for pattern in patterns:
            match = pattern.search(body_text or "")
            if not match:
                continue
            version = match.group(1) if match.groups() else None
            confidence = 0.88 if version else 0.78
            break
        if version or library_name.lower().split(".")[0] in lowered:
            detections.append(
                {
                    "name": library_name,
                    "version": version,
                    "confidence": confidence,
                }
            )
    return detections
