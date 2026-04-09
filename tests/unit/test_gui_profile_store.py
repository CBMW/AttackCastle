from __future__ import annotations

from pathlib import Path

import pytest

from attackcastle.gui.models import GuiProfile
from attackcastle.gui.profile_store import GuiProfileStore, built_in_profiles


def test_gui_profile_store_returns_builtins_when_missing(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    loaded = store.load()
    assert [item.name for item in loaded] == [item.name for item in built_in_profiles()]


def test_gui_profile_store_round_trip(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    profile = GuiProfile(
        name="Client A",
        concurrency=7,
        enable_sqlmap=True,
        output_directory="/tmp/output",
        endpoint_wordlist_path="/tmp/endpoints.txt",
        parameter_wordlist_path="/tmp/params.txt",
        payload_wordlist_path="/tmp/payloads.txt",
    )
    store.save_profile(profile)
    loaded = store.load()
    saved = next(item for item in loaded if item.name == "Client A")
    assert saved.concurrency == 7
    assert saved.enable_sqlmap is True
    assert saved.output_directory == "/tmp/output"
    assert saved.endpoint_wordlist_path == "/tmp/endpoints.txt"
    assert saved.parameter_wordlist_path == "/tmp/params.txt"
    assert saved.payload_wordlist_path == "/tmp/payloads.txt"


def test_gui_profile_store_handles_string_flags_and_invalid_numbers(tmp_path: Path) -> None:
    store_path = tmp_path / "profiles.json"
    store_path.write_text(
        """
        {
          "version": 1,
          "profiles": [
            {
              "name": "Imported",
              "base_profile": "invalid",
              "concurrency": "fast",
              "cpu_cores": "-2",
              "max_ports": "0",
              "delay_ms_between_requests": "oops",
              "rate_limit_mode": "turbo",
              "masscan_rate": "broken",
              "risk_mode": "unsafe",
              "enable_masscan": "false",
              "enable_nmap": "0",
              "enable_web_probe": "yes",
              "enable_whatweb": "no",
              "enable_sqlmap": "true",
              "export_html_report": "off",
              "export_json_data": "on"
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    loaded = GuiProfileStore(store_path).load()

    assert len(loaded) == 1
    profile = loaded[0]
    assert profile.base_profile == "prototype"
    assert profile.concurrency == 4
    assert profile.cpu_cores == 0
    assert profile.max_ports == 1000
    assert profile.delay_ms_between_requests == 100
    assert profile.rate_limit_mode == "balanced"
    assert profile.masscan_rate == 2000
    assert profile.risk_mode == "safe-active"
    assert profile.enable_masscan is False
    assert profile.enable_nmap is False
    assert profile.enable_web_probe is True
    assert profile.enable_whatweb is False
    assert profile.enable_sqlmap is True
    assert profile.export_html_report is False
    assert profile.export_json_data is True


def test_gui_profile_store_falls_back_to_builtins_on_invalid_json(tmp_path: Path) -> None:
    store_path = tmp_path / "profiles.json"
    store_path.write_text("{not valid json", encoding="utf-8")

    loaded = GuiProfileStore(store_path).load()

    assert [item.name for item in loaded] == [item.name for item in built_in_profiles()]


def test_gui_profile_store_import_rejects_invalid_payload(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    import_path = tmp_path / "import.json"
    import_path.write_text('{"profiles":"bad"}', encoding="utf-8")

    with pytest.raises(ValueError):
        store.import_from_path(import_path)


def test_gui_profile_store_save_replaces_case_insensitive_match(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_profile(GuiProfile(name="Client A", concurrency=4))

    store.save_profile(GuiProfile(name="client a", concurrency=9))

    loaded = [item for item in store.load() if item.name.casefold() == "client a"]
    assert len(loaded) == 1
    assert loaded[0].name == "client a"
    assert loaded[0].concurrency == 9


def test_gui_profile_store_delete_last_profile_is_rejected(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    store.save_all([GuiProfile(name="Only Profile")])

    with pytest.raises(ValueError, match="at least one profile"):
        store.delete_profile("Only Profile")


def test_gui_profile_store_import_rejects_case_insensitive_duplicate_names(tmp_path: Path) -> None:
    store = GuiProfileStore(tmp_path / "profiles.json")
    import_path = tmp_path / "duplicate-import.json"
    import_path.write_text(
        """
        {
          "version": 1,
          "profiles": [
            {"name": "Alpha"},
            {"name": " alpha "}
          ]
        }
        """,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate profile name"):
        store.import_from_path(import_path)
