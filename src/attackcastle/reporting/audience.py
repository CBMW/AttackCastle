from __future__ import annotations

CANONICAL_REPORT_AUDIENCES = {"executive", "client", "consultant"}
REPORT_AUDIENCE_ALIASES = {
    "client-safe": "client",
    "technical": "consultant",
}


def normalize_report_audience(audience: str | None) -> str:
    normalized = str(audience or "").strip().lower()
    if not normalized:
        return "consultant"
    if normalized in REPORT_AUDIENCE_ALIASES:
        return REPORT_AUDIENCE_ALIASES[normalized]
    if normalized in CANONICAL_REPORT_AUDIENCES:
        return normalized
    return "consultant"


def is_consultant_audience(audience: str | None) -> bool:
    return normalize_report_audience(audience) == "consultant"

