from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

ENV_PREFIX = "ATTACKCASTLE__"
_MISSING = object()


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _parse_env_value(raw: str) -> Any:
    loaded = yaml.safe_load(raw)
    if loaded is None:
        return raw
    return loaded


def _set_nested(container: dict[str, Any], parts: list[str], value: Any) -> None:
    cursor = container
    for part in parts[:-1]:
        existing = cursor.get(part)
        if not isinstance(existing, dict):
            existing = {}
            cursor[part] = existing
        cursor = existing
    cursor[parts[-1]] = value


def _get_nested(container: dict[str, Any], parts: list[str]) -> Any:
    cursor: Any = container
    for part in parts:
        if not isinstance(cursor, dict) or part not in cursor:
            return _MISSING
        cursor = cursor[part]
    return cursor


def _load_env_overrides() -> tuple[dict[str, Any], dict[str, str]]:
    overrides: dict[str, Any] = {}
    source_keys: dict[str, str] = {}
    for key, raw_value in os.environ.items():
        if not key.startswith(ENV_PREFIX):
            continue
        suffix = key[len(ENV_PREFIX) :]
        parts = [item.strip().lower() for item in suffix.split("__") if item.strip()]
        if not parts:
            continue
        parsed_value = _parse_env_value(raw_value)
        _set_nested(overrides, parts, parsed_value)
        source_keys[".".join(parts)] = key
    return overrides, source_keys


def load_config_layers(profile: str, user_config_path: str | None = None) -> dict[str, Any]:
    package_root = Path(__file__).resolve().parent
    default_path = package_root / "config" / "default.yaml"
    profile_path = package_root / "config" / "profiles" / f"{profile}.yaml"
    user_path = Path(user_config_path).expanduser().resolve() if user_config_path else None

    default_config = _load_yaml(default_path)
    profile_config = _load_yaml(profile_path)
    user_config = _load_yaml(user_path) if user_path else {}
    env_config, env_sources = _load_env_overrides()

    effective = deep_merge(default_config, profile_config)
    effective = deep_merge(effective, user_config)
    effective = deep_merge(effective, env_config)
    effective["active_profile"] = profile
    effective["config_sources"] = {
        "default": str(default_path),
        "profile": str(profile_path),
        "user": str(user_path) if user_path else None,
        "env": env_sources,
    }

    return {
        "default": default_config,
        "profile": profile_config,
        "user": user_config,
        "env": env_config,
        "env_sources": env_sources,
        "effective": effective,
        "sources": effective["config_sources"],
    }


def load_config(profile: str, user_config_path: str | None = None) -> dict[str, Any]:
    return load_config_layers(profile=profile, user_config_path=user_config_path)["effective"]


def explain_config_key(
    profile: str,
    key_path: str,
    user_config_path: str | None = None,
    cli_override: Any = _MISSING,
) -> dict[str, Any]:
    layers = load_config_layers(profile=profile, user_config_path=user_config_path)
    parts = [item.strip() for item in key_path.split(".") if item.strip()]
    if not parts:
        raise ValueError("Config key path cannot be empty.")

    layer_values: dict[str, Any] = {}
    resolved_value = _MISSING
    resolved_source = "unset"
    precedence = ["default", "profile", "user", "env"]

    for layer_name in precedence:
        value = _get_nested(layers[layer_name], parts)
        layer_values[layer_name] = None if value is _MISSING else value
        if value is not _MISSING:
            resolved_value = value
            resolved_source = layer_name

    if cli_override is not _MISSING:
        resolved_value = cli_override
        resolved_source = "cli"
        layer_values["cli"] = cli_override
    else:
        layer_values["cli"] = None

    return {
        "key": key_path,
        "value": None if resolved_value is _MISSING else resolved_value,
        "source": resolved_source,
        "layer_values": layer_values,
        "sources": layers["sources"],
    }
