from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attackcastle.gui.models import GuiProfile

PROFILE_STORE_VERSION = 1


def default_profile_store_path() -> Path:
    return Path.home() / ".attackcastle" / "gui_profiles.json"


def built_in_profiles() -> list[GuiProfile]:
    return [
        GuiProfile(
            name="Cautious",
            description="Low-noise profile for careful external validation.",
            base_profile="cautious",
            concurrency=2,
            max_ports=500,
            delay_ms_between_requests=250,
            rate_limit_mode="careful",
            masscan_rate=800,
            risk_mode="safe-active",
            enable_nikto=False,
            enable_nuclei=False,
            enable_wpscan=False,
            enable_sqlmap=False,
        ),
        GuiProfile(
            name="Standard",
            description="Balanced coverage for routine external assessments.",
            base_profile="standard",
            concurrency=4,
            max_ports=1000,
            delay_ms_between_requests=120,
            rate_limit_mode="balanced",
            masscan_rate=2000,
            risk_mode="safe-active",
            enable_wpscan=False,
            enable_sqlmap=False,
        ),
        GuiProfile(
            name="Prototype",
            description="Higher-coverage exploratory profile with richer evidence collection.",
            base_profile="prototype",
            concurrency=6,
            max_ports=1000,
            delay_ms_between_requests=60,
            rate_limit_mode="balanced",
            masscan_rate=2500,
            risk_mode="safe-active",
            enable_wpscan=True,
            enable_sqlmap=False,
        ),
        GuiProfile(
            name="Aggressive",
            description="High-intensity coverage for explicitly authorized deeper engagements.",
            base_profile="aggressive",
            concurrency=8,
            max_ports=1500,
            delay_ms_between_requests=25,
            rate_limit_mode="aggressive",
            masscan_rate=5000,
            risk_mode="aggressive",
            enable_wpscan=True,
            enable_sqlmap=True,
        ),
    ]


def _normalized_profile_name(name: str) -> str:
    return name.strip().casefold()


class GuiProfileStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_profile_store_path()

    def _read_payload(self, path: Path) -> dict[str, Any]:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("Profile store payload must be a JSON object.")
        return loaded

    def _profiles_from_payload(self, payload: dict[str, Any]) -> list[GuiProfile]:
        rows = payload.get("profiles", [])
        if not isinstance(rows, list):
            raise ValueError("Profile store payload must include a 'profiles' list.")
        loaded = [GuiProfile.from_dict(item) for item in rows if isinstance(item, dict)]
        return self._validated_profiles(loaded)

    def _validated_profiles(self, profiles: list[GuiProfile]) -> list[GuiProfile]:
        if not profiles:
            raise ValueError("Profile store must contain at least one profile.")
        seen_names: set[str] = set()
        validated: list[GuiProfile] = []
        for profile in profiles:
            normalized_name = _normalized_profile_name(profile.name)
            if not normalized_name:
                raise ValueError("Profile names cannot be blank.")
            if normalized_name in seen_names:
                raise ValueError(f"Duplicate profile name: {profile.name}")
            seen_names.add(normalized_name)
            validated.append(profile)
        return validated

    def load(self) -> list[GuiProfile]:
        return self.load_from_path(self.path)

    def load_from_path(self, path: Path) -> list[GuiProfile]:
        if not path.exists():
            return built_in_profiles()
        try:
            return self._profiles_from_payload(self._read_payload(path))
        except (OSError, ValueError, json.JSONDecodeError):
            return built_in_profiles()

    def save_all(self, profiles: list[GuiProfile]) -> Path:
        return self.save_all_to_path(self.path, profiles)

    def save_all_to_path(self, path: Path, profiles: list[GuiProfile]) -> Path:
        profiles = self._validated_profiles(profiles)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": PROFILE_STORE_VERSION,
            "profiles": [profile.to_dict() for profile in profiles],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def export_to_path(self, path: Path) -> Path:
        return self.save_all_to_path(path, self.load())

    def import_from_path(self, path: Path) -> Path:
        profiles = self._profiles_from_payload(self._read_payload(path))
        return self.save_all(profiles)

    def save_profile(self, profile: GuiProfile) -> Path:
        profiles = self.load()
        normalized_name = _normalized_profile_name(profile.name)
        if not normalized_name:
            raise ValueError("Profile names cannot be blank.")
        remaining = [item for item in profiles if _normalized_profile_name(item.name) != normalized_name]
        remaining.append(profile)
        remaining.sort(key=lambda item: item.name.lower())
        return self.save_all(remaining)

    def delete_profile(self, profile_name: str) -> Path:
        normalized_name = _normalized_profile_name(profile_name)
        profiles = [item for item in self.load() if _normalized_profile_name(item.name) != normalized_name]
        return self.save_all(profiles)
