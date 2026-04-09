from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import Any


SENSITIVE_KEY_TOKENS = ("token", "password", "secret", "api_key", "passphrase")


@dataclass
class SecretResolver:
    known_secrets: set[str] = field(default_factory=set)

    def resolve_value(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return value

        if text.startswith("env:"):
            env_key = text.split(":", 1)[1].strip()
            resolved = os.environ.get(env_key)
            if resolved:
                self.known_secrets.add(resolved)
                return resolved
            return value

        if text.startswith("secret://"):
            secret_name = text.split("://", 1)[1].strip().upper().replace("-", "_")
            env_key = f"ATTACKCASTLE_SECRET_{secret_name}"
            resolved = os.environ.get(env_key)
            if resolved:
                self.known_secrets.add(resolved)
                return resolved
            return value
        return value

    def _walk(self, node: Any, key_hint: str | None = None) -> Any:
        if isinstance(node, dict):
            updated: dict[str, Any] = {}
            for key, value in node.items():
                updated[str(key)] = self._walk(value, key_hint=str(key).lower())
            return updated
        if isinstance(node, list):
            return [self._walk(item, key_hint=key_hint) for item in node]
        if isinstance(node, str):
            resolved = self.resolve_value(node)
            if key_hint and any(token in key_hint for token in SENSITIVE_KEY_TOKENS):
                if isinstance(resolved, str) and resolved and not resolved.startswith(("env:", "secret://")):
                    self.known_secrets.add(resolved)
            return resolved
        return node

    def resolve_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return self._walk(config)

    def redact_text(self, text: str) -> str:
        redacted = str(text)
        for secret in sorted(self.known_secrets, key=len, reverse=True):
            if len(secret) < 4:
                continue
            redacted = redacted.replace(secret, "[redacted-secret]")
        return redacted


def apply_secret_resolution(config: dict[str, Any]) -> tuple[dict[str, Any], SecretResolver]:
    resolver = SecretResolver()
    resolved = resolver.resolve_config(copy.deepcopy(config))
    return resolved, resolver


def redact_sensitive_config(config: dict[str, Any]) -> dict[str, Any]:
    def _walk(node: Any, key_hint: str | None = None) -> Any:
        if isinstance(node, dict):
            return {str(key): _walk(value, key_hint=str(key).lower()) for key, value in node.items()}
        if isinstance(node, list):
            return [_walk(item, key_hint=key_hint) for item in node]
        if isinstance(node, str):
            if key_hint and any(token in key_hint for token in SENSITIVE_KEY_TOKENS):
                if node and not node.startswith(("env:", "secret://")):
                    return "[redacted-secret]"
        return node

    return _walk(copy.deepcopy(config))
