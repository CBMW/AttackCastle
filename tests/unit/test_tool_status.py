from __future__ import annotations

import sys

from attackcastle.tools.status import check_tool_status, current_platform_key


def test_tool_status_detects_installed_explicit_path() -> None:
    result = check_tool_status(
        {
            "id": "python",
            "display_name": "Python",
            "install_path": sys.executable,
            "version_command": f'"{sys.executable}" --version',
            "platforms": [current_platform_key()],
        }
    )

    assert result.installed is True
    assert result.status == "version_detected"
    assert "Python" in result.version
    assert result.exit_code == 0


def test_tool_status_marks_missing() -> None:
    result = check_tool_status(
        {
            "id": "missing",
            "display_name": "Missing",
            "executable_name": "attackcastle-definitely-missing-tool",
            "platforms": [current_platform_key()],
        }
    )

    assert result.status == "missing"
    assert result.installed is False


def test_tool_status_marks_disabled_before_checking() -> None:
    result = check_tool_status({"id": "disabled", "display_name": "Disabled", "enabled": False})

    assert result.status == "disabled"
    assert result.enabled is False


def test_tool_status_marks_unavailable_platform() -> None:
    platform = current_platform_key()
    unavailable = next(item for item in ("linux", "windows", "darwin") if item != platform)

    result = check_tool_status({"id": "tool", "display_name": "Tool", "platforms": [unavailable]})

    assert result.status == "unavailable"
    assert result.available_on_platform is False


def test_tool_status_reports_detection_failure_without_crashing() -> None:
    result = check_tool_status(
        {
            "id": "bad",
            "display_name": "Bad",
            "detection_command": f'"{sys.executable}" -c "import sys; print(\'nope\'); sys.exit(7)"',
            "platforms": [current_platform_key()],
        }
    )

    assert result.status == "missing"
    assert result.exit_code == 7
    assert "nope" in result.stdout
