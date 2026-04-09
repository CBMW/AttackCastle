from __future__ import annotations

from attackcastle.config_loader import explain_config_key


def test_explain_config_key_reports_env_source(monkeypatch):
    monkeypatch.setenv("ATTACKCASTLE__SCAN__MAX_PORTS", "123")
    explained = explain_config_key(profile="cautious", key_path="scan.max_ports")
    assert explained["source"] == "env"
    assert explained["value"] == 123


def test_explain_config_key_reports_cli_override():
    explained = explain_config_key(
        profile="cautious",
        key_path="scan.max_ports",
        cli_override=456,
    )
    assert explained["source"] == "cli"
    assert explained["value"] == 456
