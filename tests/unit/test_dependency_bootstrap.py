from __future__ import annotations

from io import StringIO

from rich.console import Console

from attackcastle import cli


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False, color_system=None)


def test_external_dependency_rows_include_expected_tools(monkeypatch) -> None:
    def fake_which(command: str) -> str | None:
        if command == "nmap":
            return "/usr/bin/nmap"
        return None

    monkeypatch.setattr(cli.shutil, "which", fake_which)

    rows = cli._external_dependency_rows()
    commands = {row["command"] for row in rows}
    assert {"nmap", "whatweb", "nikto", "nuclei", "wpscan", "sqlmap"} <= commands
    nmap_row = next(row for row in rows if row["command"] == "nmap")
    assert nmap_row["available"] is True
    assert nmap_row["apt_package"] == "nmap"
    assert "validation_status" in nmap_row


def test_missing_dependency_message_is_sorted() -> None:
    rows = [
        {"command": "sqlmap", "available": False},
        {"command": "nmap", "available": False},
        {"command": "nikto", "available": True},
    ]
    assert cli._missing_dependency_message(rows) == "nmap, sqlmap"


def test_install_dependencies_dry_run_returns_planned_packages() -> None:
    rows = [
        {"command": "nmap", "apt_package": "nmap", "available": False},
        {"command": "sqlmap", "apt_package": "sqlmap", "available": False},
    ]
    summary = cli._install_dependencies_with_apt(
        console=_console(),
        output_format="json",
        rows=rows,
        assume_yes=True,
        dry_run=True,
    )
    assert summary["error"] is None
    assert summary["dry_run"] is True
    assert summary["packages"] == ["nmap", "sqlmap"]
    assert summary["installed_packages"] == []
