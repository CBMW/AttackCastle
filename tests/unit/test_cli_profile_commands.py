from __future__ import annotations

import json

from typer.testing import CliRunner

from attackcastle.cli import app


def test_profile_show_lists_new_profile_metadata() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["profile", "show", "bug_bounty", "--output-format", "json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["profile"] == "bug_bounty"
    assert payload["risk_mode"] == "safe-active"
    assert "nuclei" in payload["enabled_modules"]


def test_plan_diff_compares_profiles_for_same_target() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["plan-diff", "stealth", "full", "--target", "example.com", "--output-format", "json"],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["profile_a"] == "stealth"
    assert payload["profile_b"] == "full"
    assert payload["difference_count"] >= 1
