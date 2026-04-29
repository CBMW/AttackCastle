from __future__ import annotations

import sys
from pathlib import Path

from attackcastle.tools.installer import run_shell_command


def test_tool_installer_captures_output_and_exit_code(tmp_path: Path) -> None:
    result = run_shell_command(
        f'"{sys.executable}" -c "import sys; print(\'out\'); print(\'err\', file=sys.stderr)"',
        timeout_seconds=5,
        log_dir=tmp_path,
        artifact_prefix="capture",
    )

    assert result.exit_code == 0
    assert "out" in result.stdout
    assert "err" in result.stderr
    assert Path(result.stdout_path).exists()
    assert Path(result.stderr_path).exists()
    assert Path(result.transcript_path).exists()


def test_tool_installer_enforces_timeout() -> None:
    result = run_shell_command(f'"{sys.executable}" -c "import time; time.sleep(2)"', timeout_seconds=1)

    assert result.timed_out is True
    assert result.exit_code is None
    assert "timeout" in str(result.error).lower()


def test_tool_installer_reports_missing_command() -> None:
    result = run_shell_command("")

    assert result.error == "install command not configured"
    assert result.exit_code is None


def test_tool_installer_preserves_exact_command_text() -> None:
    command = f'"{sys.executable}" --version'

    result = run_shell_command(command)

    assert result.command == command
