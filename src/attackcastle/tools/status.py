from __future__ import annotations

import platform
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from attackcastle.tools.installer import ToolCommandResult, run_shell_command
from attackcastle.tools.schema import normalize_tool_definition


@dataclass(slots=True)
class ToolCheckResult:
    status: str
    installed: bool
    available_on_platform: bool
    enabled: bool
    detected_path: str = ""
    version: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    command: str = ""
    message: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


ToolStatus = ToolCheckResult


def current_platform_key() -> str:
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "darwin":
        return "darwin"
    return "linux"


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _command_with_executable(definition: dict[str, Any], command: str, detected_path: str) -> str:
    executable = str(definition.get("executable_name") or "").strip()
    if not executable or not detected_path:
        return command
    if command == executable or command.startswith(executable + " "):
        return detected_path + command[len(executable) :]
    return command


def _run_probe(definition: dict[str, Any], command: str, detected_path: str) -> ToolCommandResult:
    rendered = _command_with_executable(definition, command, detected_path)
    return run_shell_command(rendered, timeout_seconds=min(int(definition.get("timeout_seconds") or 300), 30))


def check_tool_status(definition: dict[str, Any]) -> ToolCheckResult:
    tool = normalize_tool_definition(definition)
    if not tool["enabled"]:
        return ToolCheckResult(
            status="disabled",
            installed=False,
            available_on_platform=True,
            enabled=False,
            message="disabled",
        )
    platform_key = current_platform_key()
    if platform_key not in tool["platforms"]:
        return ToolCheckResult(
            status="unavailable",
            installed=False,
            available_on_platform=False,
            enabled=True,
            message="unavailable on this platform",
        )

    detected_path = ""
    install_path = str(tool.get("install_path") or "").strip()
    if install_path and Path(install_path).exists():
        detected_path = str(Path(install_path))
    if not detected_path and tool.get("executable_name"):
        detected_path = shutil.which(str(tool["executable_name"])) or ""

    detection = str(tool.get("detection_command") or "").strip()
    version_command = str(tool.get("version_command") or "").strip()
    command = detection or version_command
    probe: ToolCommandResult | None = None
    if command:
        probe = _run_probe(tool, command, detected_path)
        if probe.exit_code == 0 and not detected_path:
            detected_path = shutil.which(str(tool.get("executable_name") or "")) or detected_path
    installed = bool(detected_path)
    if probe is not None and probe.exit_code == 0:
        installed = True
    if not installed:
        return ToolCheckResult(
            status="missing",
            installed=False,
            available_on_platform=True,
            enabled=True,
            stdout=probe.stdout if probe else "",
            stderr=probe.stderr if probe else "",
            exit_code=probe.exit_code if probe else None,
            command=probe.command if probe else command,
            message="missing",
        )

    version = ""
    if version_command:
        version_probe = _run_probe(tool, version_command, detected_path)
        version = _first_line(version_probe.stdout) or _first_line(version_probe.stderr)
        probe = version_probe
    elif probe is not None:
        version = _first_line(probe.stdout) or _first_line(probe.stderr)
    return ToolCheckResult(
        status="version_detected" if version else "installed",
        installed=True,
        available_on_platform=True,
        enabled=True,
        detected_path=detected_path,
        version=version,
        stdout=probe.stdout if probe else "",
        stderr=probe.stderr if probe else "",
        exit_code=probe.exit_code if probe else 0,
        command=probe.command if probe else command,
        message="version detected" if version else "installed",
    )
