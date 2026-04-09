from __future__ import annotations

from typing import Any


DEFAULT_RISK_MODES: dict[str, dict[str, Any]] = {
    "passive": {
        "blocked_capabilities": [
            "network_port_scan",
            "web_vuln_scan",
            "web_template_scan",
            "web_injection_scan",
            "cms_wordpress_scan",
            "cms_framework_scan",
            "service_exposure_checks",
        ],
        "allow_sqlmap": False,
        "allow_auth_bruteforce": False,
        "allow_heavy_templates": False,
        "max_sqlmap_targets": 0,
    },
    "safe-active": {
        "blocked_capabilities": [],
        "allow_sqlmap": False,
        "allow_auth_bruteforce": False,
        "allow_heavy_templates": False,
        "max_sqlmap_targets": 6,
    },
    "aggressive": {
        "blocked_capabilities": [],
        "allow_sqlmap": True,
        "allow_auth_bruteforce": True,
        "allow_heavy_templates": True,
        "max_sqlmap_targets": 20,
    },
}


def _normalize_mode(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"safe", "safe_active", "safeactive"}:
        return "safe-active"
    if normalized in {"passive", "safe-active", "aggressive"}:
        return normalized
    return ""


def resolve_risk_mode(
    profile_name: str,
    config: dict[str, Any],
    requested_mode: str | None = None,
) -> tuple[str, dict[str, Any]]:
    profile = str(profile_name or "").strip().lower()
    configured = config.get("risk_modes", {}) if isinstance(config.get("risk_modes"), dict) else {}
    mode_by_profile = configured.get("mode_by_profile", {})
    if not isinstance(mode_by_profile, dict):
        mode_by_profile = {}
    default_mode = _normalize_mode(configured.get("default_mode")) or "safe-active"

    selected_mode = (
        _normalize_mode(requested_mode)
        or _normalize_mode(config.get("scan", {}).get("risk_mode"))
        or _normalize_mode(mode_by_profile.get(profile))
        or default_mode
    )
    if selected_mode not in DEFAULT_RISK_MODES:
        selected_mode = "safe-active"

    configured_modes = configured.get("modes", {})
    if not isinstance(configured_modes, dict):
        configured_modes = {}
    selected_base = dict(DEFAULT_RISK_MODES[selected_mode])
    selected_override = configured_modes.get(selected_mode, {})
    if isinstance(selected_override, dict):
        selected_base.update(selected_override)

    blocked_capabilities = selected_base.get("blocked_capabilities", [])
    if not isinstance(blocked_capabilities, list):
        blocked_capabilities = []
    selected_base["blocked_capabilities"] = [str(item) for item in blocked_capabilities]
    selected_base["allow_sqlmap"] = bool(selected_base.get("allow_sqlmap", False))
    selected_base["allow_auth_bruteforce"] = bool(selected_base.get("allow_auth_bruteforce", False))
    selected_base["allow_heavy_templates"] = bool(selected_base.get("allow_heavy_templates", False))
    selected_base["max_sqlmap_targets"] = max(0, int(selected_base.get("max_sqlmap_targets", 6)))

    return selected_mode, selected_base


def risk_controls_from_context(context: Any) -> dict[str, Any]:
    controls = context.config.get("risk_mode_controls", {})
    if not isinstance(controls, dict):
        return {}
    return controls
