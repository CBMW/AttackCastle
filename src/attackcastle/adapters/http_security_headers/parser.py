from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

CORE_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)
SUPPORTING_HEADERS = (
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "Server",
    "X-Powered-By",
)
CHECKED_HEADERS = (*CORE_HEADERS, *SUPPORTING_HEADERS)
ALLOWED_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}
DEFAULT_HSTS_MIN_SECONDS = 15552000


@dataclass(slots=True)
class ParsedHeaderResponse:
    status_code: int | None
    headers: dict[str, str]
    raw_headers: str


def normalize_header_map(headers: dict[str, Any] | list[dict[str, Any]] | list[tuple[str, Any]]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    if isinstance(headers, dict):
        items = headers.items()
    else:
        items = []
        for item in headers:
            if isinstance(item, dict):
                key = str(item.get("name") or "").strip()
                value = item.get("value")
                items.append((key, value))
            elif isinstance(item, tuple) and len(item) == 2:
                items.append(item)
    for raw_key, raw_value in items:
        key = str(raw_key or "").strip().lower()
        if not key:
            continue
        if isinstance(raw_value, list):
            value = ", ".join(str(part).strip() for part in raw_value if str(part).strip())
        else:
            value = str(raw_value or "").strip()
        normalized[key] = value
    return normalized


def parse_raw_response_headers(raw_text: str) -> ParsedHeaderResponse:
    text = str(raw_text or "").replace("\r\n", "\n")
    if not text.strip():
        return ParsedHeaderResponse(status_code=None, headers={}, raw_headers="")

    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.split("\n"):
        stripped = line.rstrip("\r")
        if stripped.startswith("HTTP/"):
            if current:
                blocks.append(current)
            current = [stripped]
            continue
        if not current:
            continue
        if not stripped and current:
            blocks.append(current)
            current = []
            continue
        current.append(stripped)
    if current:
        blocks.append(current)

    if not blocks:
        return ParsedHeaderResponse(status_code=None, headers={}, raw_headers=text.strip())

    selected = blocks[-1]
    for block in reversed(blocks):
        status_code = _status_code_from_status_line(block[0])
        if status_code != 100:
            selected = block
            break

    headers: dict[str, str] = {}
    current_name = ""
    for line in selected[1:]:
        if not line:
            continue
        if line[:1] in {" ", "\t"} and current_name:
            headers[current_name] = f"{headers[current_name]} {line.strip()}".strip()
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        current_name = name.strip().lower()
        headers[current_name] = value.strip()
    return ParsedHeaderResponse(
        status_code=_status_code_from_status_line(selected[0]),
        headers=headers,
        raw_headers="\n".join(selected).strip(),
    )


def build_header_analysis(
    *,
    url: str,
    status_code: int | None,
    headers: dict[str, str],
    raw_headers: str,
    hsts_min_seconds: int = DEFAULT_HSTS_MIN_SECONDS,
) -> dict[str, Any]:
    normalized_headers = normalize_header_map(headers)
    parsed_url = urlparse(str(url or ""))
    is_https = parsed_url.scheme.lower() == "https"
    header_rows: list[dict[str, str]] = []
    core_missing: list[str] = []
    core_weak: list[str] = []
    supporting_missing: list[str] = []
    supporting_exposed: list[str] = []

    for header_name in CHECKED_HEADERS:
        value = normalized_headers.get(header_name.lower(), "")
        if header_name == "Strict-Transport-Security":
            status, reason = _evaluate_hsts(value, is_https=is_https, minimum_seconds=hsts_min_seconds)
        elif header_name == "Content-Security-Policy":
            status, reason = _evaluate_csp(value)
        elif header_name == "X-Frame-Options":
            status, reason = _evaluate_x_frame_options(value)
        elif header_name == "X-Content-Type-Options":
            status, reason = _evaluate_x_content_type_options(value)
        elif header_name == "Referrer-Policy":
            status, reason = _evaluate_referrer_policy(value)
        elif header_name in {"Server", "X-Powered-By"}:
            status, reason = _evaluate_exposed_header(value)
        else:
            status, reason = _evaluate_presence(value)
        row = {
            "header": header_name,
            "status": status,
            "value": value,
            "reason": reason,
        }
        header_rows.append(row)
        if header_name in CORE_HEADERS:
            if status == "Missing":
                core_missing.append(header_name)
            elif status == "Weak":
                core_weak.append(header_name)
        else:
            if status == "Missing":
                supporting_missing.append(header_name)
            elif status == "Exposed":
                supporting_exposed.append(header_name)

    return {
        "url": str(url or ""),
        "status_code": status_code,
        "headers": header_rows,
        "raw_headers": raw_headers,
        "core_missing": core_missing,
        "core_weak": core_weak,
        "supporting_missing": supporting_missing,
        "supporting_exposed": supporting_exposed,
        "trigger_finding": bool(core_missing or core_weak),
    }


def summarize_analysis(analysis: dict[str, Any]) -> str:
    url = str(analysis.get("url") or "")
    status_code = analysis.get("status_code")
    core_missing = ", ".join(analysis.get("core_missing", [])) or "none"
    core_weak = ", ".join(analysis.get("core_weak", [])) or "none"
    return f"{url} status={status_code} missing={core_missing} weak={core_weak}"


def _status_code_from_status_line(line: str) -> int | None:
    parts = str(line or "").split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except (TypeError, ValueError):
        return None


def _evaluate_hsts(value: str, *, is_https: bool, minimum_seconds: int) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not present.")
    lowered = value.lower()
    max_age = None
    for token in lowered.split(";"):
        token = token.strip()
        if not token.startswith("max-age="):
            continue
        try:
            max_age = int(token.split("=", 1)[1].strip())
        except (TypeError, ValueError):
            max_age = None
        break
    if max_age is None:
        return ("Weak", "max-age is missing or invalid.")
    if max_age < int(minimum_seconds):
        return ("Weak", f"max-age={max_age} is below the minimum hardening threshold.")
    if is_https and "includesubdomains" not in lowered:
        return ("Weak", "includeSubDomains is missing.")
    return ("Present", "Header is configured.")


def _evaluate_csp(value: str) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not present.")
    lowered = value.lower()
    weak_tokens = ("'unsafe-inline'", "'unsafe-eval'", " *", "* ", "default-src *", "script-src *", "style-src *")
    if any(token in lowered for token in weak_tokens) or "*" in lowered:
        return ("Weak", "Policy contains unsafe or wildcard directives.")
    return ("Present", "Header is configured.")


def _evaluate_x_frame_options(value: str) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not present.")
    normalized = value.strip().upper()
    if normalized in {"DENY", "SAMEORIGIN"}:
        return ("Present", "Header is configured.")
    return ("Weak", "Only DENY or SAMEORIGIN are treated as valid.")


def _evaluate_x_content_type_options(value: str) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not present.")
    if value.strip().lower() == "nosniff":
        return ("Present", "Header is configured.")
    return ("Weak", "Only nosniff is treated as valid.")


def _evaluate_referrer_policy(value: str) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not present.")
    policies = [item.strip().lower() for item in value.split(",") if item.strip()]
    if any(item in ALLOWED_REFERRER_POLICIES for item in policies):
        return ("Present", "Header is configured.")
    return ("Weak", "Policy is more permissive than the accepted hardened options.")


def _evaluate_exposed_header(value: str) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not exposed.")
    return ("Exposed", "Header exposes implementation detail.")


def _evaluate_presence(value: str) -> tuple[str, str]:
    if not value:
        return ("Missing", "Header is not present.")
    return ("Present", "Header is configured.")
