from __future__ import annotations

import json

from typer.testing import CliRunner

from attackcastle.cli import app
from attackcastle.scope.parser import summarize_target_input


def test_summarize_target_input_counts_duplicates_and_invalid() -> None:
    summary = summarize_target_input("example.com,example.com,10.0.0.1,bad target")
    assert summary.total_entries == 4
    assert summary.valid_entries == 2
    assert summary.invalid_entries == 1
    assert summary.duplicates_removed == 1
    assert summary.by_type["domain"] == 2
    assert summary.by_type["single_ip"] == 1


def test_scope_validate_command_supports_multi_source_targets(tmp_path) -> None:
    runner = CliRunner()
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\nbad target\n10.10.10.0/24\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scope",
            "validate",
            "--targets",
            str(scope_file),
            "--targets",
            "example.com",
            "--output-format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["valid_entries"] == 2
    assert payload["invalid_entries"] == 1
    assert payload["duplicates_removed"] == 1
    assert payload["by_type"]["domain"] == 2
    assert payload["by_type"]["cidr"] == 1
