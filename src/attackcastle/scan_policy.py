from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    profile: str
    global_rate_limit: int
    global_concurrency: int
    http_rate_limit: int
    dns_rate_limit: int
    port_scan_rate: int
    nuclei_rate_limit: int
    ferox_threads: int
    subfinder_rate_limit: int
    enable_intrusive_checks: bool
    enable_full_port_scan: bool
    top_ports: str
    nmap_version_intensity: str
    nuclei_tags: list[str]


def _profile_name(profile_name: str) -> str:
    normalized = str(profile_name or "").strip().lower()
    if normalized in {"prototype", "standard", "external_pentest", ""}:
        return "balanced"
    if normalized in {"full"}:
        return "aggressive"
    return normalized


def build_scan_policy(profile_name: str, config: dict[str, Any]) -> ScanPolicy:
    profile = _profile_name(profile_name)
    defaults: dict[str, dict[str, Any]] = {
        "cautious": {
            "global_rate_limit": 50,
            "global_concurrency": 4,
            "http_rate_limit": 10,
            "dns_rate_limit": 20,
            "port_scan_rate": 300,
            "nuclei_rate_limit": 5,
            "ferox_threads": 4,
            "subfinder_rate_limit": 2,
            "enable_intrusive_checks": False,
            "enable_full_port_scan": False,
            "top_ports": "1-1000",
            "nmap_version_intensity": "--version-light",
            "nuclei_tags": ["cve", "exposure", "misconfig"],
        },
        "balanced": {
            "global_rate_limit": 100,
            "global_concurrency": 8,
            "http_rate_limit": 25,
            "dns_rate_limit": 50,
            "port_scan_rate": 1000,
            "nuclei_rate_limit": 15,
            "ferox_threads": 12,
            "subfinder_rate_limit": 5,
            "enable_intrusive_checks": False,
            "enable_full_port_scan": False,
            "top_ports": "1-1000",
            "nmap_version_intensity": "",
            "nuclei_tags": ["cve", "exposure", "misconfig", "default-login"],
        },
        "aggressive": {
            "global_rate_limit": 200,
            "global_concurrency": 12,
            "http_rate_limit": 50,
            "dns_rate_limit": 100,
            "port_scan_rate": 3000,
            "nuclei_rate_limit": 30,
            "ferox_threads": 24,
            "subfinder_rate_limit": 10,
            "enable_intrusive_checks": True,
            "enable_full_port_scan": True,
            "top_ports": "1-65535",
            "nmap_version_intensity": "--version-all",
            "nuclei_tags": ["cve", "exposure", "misconfig", "default-login", "tech", "panel"],
        },
    }
    selected = dict(defaults.get(profile, defaults["balanced"]))

    scan_config = config.get("scan", {})
    if isinstance(scan_config, dict):
        if isinstance(scan_config.get("max_ports"), int) and int(scan_config["max_ports"]) <= 1000:
            selected["top_ports"] = "1-1000"
    return ScanPolicy(profile=profile, **selected)
