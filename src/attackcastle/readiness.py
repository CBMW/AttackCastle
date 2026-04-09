from __future__ import annotations

import io
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console


EXTERNAL_DEPENDENCY_SPECS = (
    {
        "check": "subfinder_binary",
        "command": "subfinder",
        "apt_package": "subfinder",
        "suggestion": "Install subfinder for passive subdomain enumeration.",
    },
    {
        "check": "dnsx_binary",
        "command": "dnsx",
        "apt_package": "dnsx",
        "suggestion": "Install dnsx for high-speed DNS resolution.",
    },
    {
        "check": "nmap_binary",
        "command": "nmap",
        "apt_package": "nmap",
        "suggestion": "Install nmap for service detection coverage.",
    },
    {
        "check": "masscan_binary",
        "command": "masscan",
        "apt_package": "masscan",
        "suggestion": "Install masscan for high-speed discovery stage.",
    },
    {
        "check": "httpx_binary",
        "command": "httpx",
        "apt_package": "httpx-toolkit",
        "suggestion": "Install httpx for web service discovery and metadata collection.",
    },
    {
        "check": "openssl_binary",
        "command": "openssl",
        "apt_package": "openssl",
        "suggestion": "Install openssl for certificate and TLS inspection.",
    },
    {
        "check": "curl_binary",
        "command": "curl",
        "apt_package": "curl",
        "suggestion": "Install curl for active validation and replay workflows.",
    },
    {
        "check": "whatweb_binary",
        "command": "whatweb",
        "apt_package": "whatweb",
        "suggestion": "Install whatweb for web technology fingerprinting.",
    },
    {
        "check": "nikto_binary",
        "command": "nikto",
        "apt_package": "nikto",
        "suggestion": "Install nikto for web vulnerability heuristics.",
    },
    {
        "check": "nuclei_binary",
        "command": "nuclei",
        "apt_package": "nuclei",
        "suggestion": "Install nuclei for template-based vulnerability scanning.",
    },
    {
        "check": "wpscan_binary",
        "command": "wpscan",
        "apt_package": "wpscan",
        "suggestion": "Install wpscan for WordPress-specific scanning.",
    },
    {
        "check": "sqlmap_binary",
        "command": "sqlmap",
        "apt_package": "sqlmap",
        "suggestion": "Install sqlmap for injection testing workflows.",
    },
    {
        "check": "ffuf_binary",
        "command": "ffuf",
        "apt_package": "ffuf",
        "suggestion": "Install ffuf for virtual host and content discovery workflows.",
    },
    {
        "check": "katana_binary",
        "command": "katana",
        "apt_package": "katana",
        "suggestion": "Install katana for web crawling and endpoint discovery.",
    },
    {
        "check": "feroxbuster_binary",
        "command": "feroxbuster",
        "apt_package": "feroxbuster",
        "suggestion": "Install feroxbuster for content discovery.",
    },
)

CAPABILITY_TOOL_MAPPING: dict[str, tuple[str, str, str]] = {
    "subdomain_enumeration": ("subfinder", "subfinder", "Enumerating subdomains"),
    "network_fast_scan": ("masscan", "masscan", "Running Masscan discovery"),
    "network_port_scan": ("nmap", "nmap", "Running Nmap"),
    "dns_resolution": ("dnsx", "dnsx", "Resolving hosts"),
    "web_probe": ("httpx", "httpx", "Probing web services"),
    "vhost_discovery": ("ffuf", "ffuf", "Discovering virtual hosts"),
    "web_discovery": ("katana", "katana", "Discovering web endpoints"),
    "request_capture": ("python_stdlib", "python", "Capturing replayable requests"),
    "surface_intelligence": ("internal", "python", "Correlating surface intelligence"),
    "tls_probe": ("openssl", "openssl", "Detecting TLS and certificates"),
    "service_exposure_checks": ("internal", "python", "Analyzing service exposure"),
    "active_validation_core": ("curl", "curl", "Running active validation"),
    "web_fingerprint": ("whatweb", "whatweb", "Fingerprinting web technologies"),
    "web_vuln_scan": ("nikto", "nikto", "Running Nikto web checks"),
    "web_template_scan": ("nuclei", "nuclei", "Running Nuclei template checks"),
    "web_injection_scan": ("sqlmap", "sqlmap", "Running SQLMap"),
    "cms_wordpress_scan": ("wpscan", "wpscan", "Running WPScan"),
    "cms_framework_scan": ("nuclei", "nuclei", "Running framework checks"),
    "vuln_enrichment": ("internal", "python", "Enriching services with CVEs"),
    "findings_engine": ("internal", "python", "Generating findings"),
    "reporting": ("internal", "python", "Building report"),
}


@dataclass(slots=True)
class ReadinessReport:
    status: str
    can_launch: bool
    partial_run: bool
    risk_mode: str
    missing_tools: list[str]
    tool_impact: list[dict[str, Any]]
    blocked_capabilities: list[str]
    recommended_actions: list[str]
    selected_task_count: int = 0
    runnable_task_count: int = 0
    blocked_task_count: int = 0
    assessment_mode: str = "generic"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DependencyInstallSupport:
    supported: bool
    reason: str
    platform: str
    command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def capability_tool(capability: str) -> tuple[str, str]:
    tool_name, command, _label = CAPABILITY_TOOL_MAPPING.get(
        capability,
        ("internal", "python", capability.replace("_", " ")),
    )
    return tool_name, command


def capability_label(capability: str) -> str:
    _tool_name, _command, label = CAPABILITY_TOOL_MAPPING.get(
        capability,
        ("internal", "python", capability.replace("_", " ")),
    )
    return label


def external_dependency_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in EXTERNAL_DEPENDENCY_SPECS:
        command_name = str(spec["command"])
        resolved = shutil.which(command_name)
        rows.append(
            {
                "check": str(spec["check"]),
                "command": command_name,
                "apt_package": str(spec["apt_package"]),
                "suggestion": str(spec["suggestion"]),
                "available": bool(resolved),
                "resolved_path": resolved,
            }
        )
    return rows


def missing_dependency_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if not bool(row.get("available"))]


def missing_dependency_message(rows: list[dict[str, Any]]) -> str:
    missing = missing_dependency_rows(rows)
    if not missing:
        return ""
    return ", ".join(sorted(str(row["command"]) for row in missing))


def dependency_install_support() -> DependencyInstallSupport:
    platform = "posix" if os.name == "posix" else os.name
    if os.name != "posix":
        return DependencyInstallSupport(
            supported=False,
            reason="Automatic dependency installs are only supported on Linux/POSIX hosts with apt-get.",
            platform=platform,
        )
    apt_get = shutil.which("apt-get")
    if not apt_get:
        return DependencyInstallSupport(
            supported=False,
            reason="apt-get was not found in PATH. Install scanner tools manually or use a Linux host with apt-get.",
            platform=platform,
        )
    return DependencyInstallSupport(
        supported=True,
        reason="apt-get is available for grouped dependency installation.",
        platform=platform,
        command=apt_get,
    )


def _tool_impact_entry(command: str) -> dict[str, Any]:
    return {
        "tool": command,
        "capabilities": [],
        "task_labels": [],
    }


def _append_tool_impact(bucket: dict[str, Any], capability: str, label: str) -> None:
    capabilities = bucket.setdefault("capabilities", [])
    if capability not in capabilities:
        capabilities.append(capability)
    task_labels = bucket.setdefault("task_labels", [])
    if label not in task_labels:
        task_labels.append(label)


def _generic_tool_impact(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    impact_by_command: dict[str, dict[str, Any]] = {}
    for capability, (_tool_name, command, label) in CAPABILITY_TOOL_MAPPING.items():
        if command == "python":
            continue
        if not any(str(row.get("command")) == command and not bool(row.get("available")) for row in rows):
            continue
        bucket = impact_by_command.setdefault(command, _tool_impact_entry(command))
        _append_tool_impact(bucket, capability, label)
    return [impact_by_command[key] for key in sorted(impact_by_command)]


def _recommended_actions(
    *,
    missing_tools: list[str],
    blocked_capabilities: list[str],
    install_support: DependencyInstallSupport,
    status: str,
    targeted: bool,
    error: str | None = None,
) -> list[str]:
    actions: list[str] = []
    if error:
        actions.append("Review the target input, profile, and override config before launching again.")
        actions.append(error)
        return actions
    if missing_tools:
        if install_support.supported:
            actions.append("Install missing tools with `attackcastle doctor --install-missing --yes` or `attackcastle plugins install-missing --yes`.")
        else:
            actions.append(install_support.reason)
        if blocked_capabilities:
            actions.append("Planned capability coverage will be reduced for: " + ", ".join(blocked_capabilities))
    if status == "partial" and targeted:
        actions.append("AttackCastle can still launch, but expect a partial run with reduced discovery or validation coverage.")
    if status == "blocked" and targeted:
        actions.append("Current tool coverage would leave no runnable planned tasks for this target and profile. Install the missing tools before launching.")
    if not actions:
        actions.append("Current environment is ready for the selected workflow.")
    return actions


def assess_readiness(
    *,
    target_input: str | None = None,
    profile: str = "prototype",
    user_config_path: str | None = None,
    risk_mode: str | None = None,
    forced_target_type: str | None = None,
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    max_hosts: int | None = None,
    max_ports: int | None = None,
    proxy_url: str | None = None,
    disable_proxy: bool = False,
    dependency_rows: list[dict[str, Any]] | None = None,
) -> ReadinessReport:
    rows = dependency_rows or external_dependency_rows()
    install_support = dependency_install_support()
    missing_tools = sorted(str(row["command"]) for row in missing_dependency_rows(rows))

    if not target_input or not target_input.strip():
        tool_impact = _generic_tool_impact(rows)
        blocked_capabilities = sorted(
            {
                capability
                for entry in tool_impact
                for capability in entry.get("capabilities", [])
            }
        )
        status = "ready" if not missing_tools else "partial"
        return ReadinessReport(
            status=status,
            can_launch=True,
            partial_run=bool(missing_tools),
            risk_mode=risk_mode or "unknown",
            missing_tools=missing_tools,
            tool_impact=tool_impact,
            blocked_capabilities=blocked_capabilities,
            recommended_actions=_recommended_actions(
                missing_tools=missing_tools,
                blocked_capabilities=blocked_capabilities,
                install_support=install_support,
                status=status,
                targeted=False,
            ),
            assessment_mode="generic",
        )

    temp_root = Path(tempfile.mkdtemp(prefix="attackcastle-readiness-"))
    try:
        from attackcastle.app import ScanOptions, build_scan_plan

        silent_console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        options = ScanOptions(
            target_input=target_input,
            output_directory=str(temp_root),
            profile=profile,
            forced_target_type=forced_target_type,
            user_config_path=user_config_path,
            dry_run=True,
            allow=allow or [],
            deny=deny or [],
            max_hosts=max_hosts,
            max_ports=max_ports,
            rich_ui=False,
            emit_plain_logs=False,
            risk_mode=risk_mode,
            proxy_url=proxy_url,
            disable_proxy=disable_proxy,
        )
        plan_bundle, _run_store = build_scan_plan(options, console=silent_console)
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
        return ReadinessReport(
            status="blocked",
            can_launch=False,
            partial_run=False,
            risk_mode=risk_mode or "unknown",
            missing_tools=missing_tools,
            tool_impact=[],
            blocked_capabilities=[],
            recommended_actions=_recommended_actions(
                missing_tools=missing_tools,
                blocked_capabilities=[],
                install_support=install_support,
                status="blocked",
                targeted=True,
                error=error,
            ),
            assessment_mode="targeted",
            error=error,
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    items = plan_bundle.get("plan_payload", {}).get("items", [])
    risk_mode_value = str(plan_bundle.get("plan_payload", {}).get("risk_mode") or risk_mode or "unknown")
    dependency_lookup = {str(row["command"]): row for row in rows}
    selected_task_count = 0
    runnable_task_count = 0
    blocked_task_count = 0
    tool_impact_by_command: dict[str, dict[str, Any]] = {}

    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict) or not item.get("selected"):
                continue
            selected_task_count += 1
            capability = str(item.get("capability") or "")
            label = str(item.get("label") or capability_label(capability))
            _tool_name, command = capability_tool(capability)
            if command == "python" or bool(dependency_lookup.get(command, {}).get("available")):
                runnable_task_count += 1
                continue
            blocked_task_count += 1
            bucket = tool_impact_by_command.setdefault(command, _tool_impact_entry(command))
            _append_tool_impact(bucket, capability, label)

    tool_impact = [tool_impact_by_command[key] for key in sorted(tool_impact_by_command)]
    blocked_capabilities = sorted(
        {
            capability
            for entry in tool_impact
            for capability in entry.get("capabilities", [])
        }
    )
    can_launch = selected_task_count > 0 and runnable_task_count > 0
    partial_run = blocked_task_count > 0 and can_launch
    status = "blocked" if not can_launch else "partial" if partial_run else "ready"

    return ReadinessReport(
        status=status,
        can_launch=can_launch,
        partial_run=partial_run,
        risk_mode=risk_mode_value,
        missing_tools=missing_tools,
        tool_impact=tool_impact,
        blocked_capabilities=blocked_capabilities,
        recommended_actions=_recommended_actions(
            missing_tools=missing_tools,
            blocked_capabilities=blocked_capabilities,
            install_support=install_support,
            status=status,
            targeted=True,
        ),
        selected_task_count=selected_task_count,
        runnable_task_count=runnable_task_count,
        blocked_task_count=blocked_task_count,
        assessment_mode="targeted",
    )
