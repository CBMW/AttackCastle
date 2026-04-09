from __future__ import annotations

from attackcastle.security import SecretResolver, apply_secret_resolution


def test_apply_secret_resolution_resolves_env_and_secret_uri(monkeypatch):
    monkeypatch.setenv("WPSCAN_TOKEN", "token-from-env-1234")
    monkeypatch.setenv("ATTACKCASTLE_SECRET_WP_TOKEN", "token-from-secret-uri-5678")
    original = {
        "wpscan": {
            "api_token": "env:WPSCAN_TOKEN",
            "fallback_token": "secret://wp-token",
        }
    }
    resolved, resolver = apply_secret_resolution(original)

    assert resolved["wpscan"]["api_token"] == "token-from-env-1234"
    assert resolved["wpscan"]["fallback_token"] == "token-from-secret-uri-5678"
    assert original["wpscan"]["api_token"] == "env:WPSCAN_TOKEN"
    assert resolver.redact_text("wpscan --api-token token-from-env-1234").endswith("[redacted-secret]")
    assert resolver.redact_text("token-from-secret-uri-5678") == "[redacted-secret]"


def test_secret_resolver_collects_sensitive_literal_values():
    resolver = SecretResolver()
    resolved = resolver.resolve_config({"auth": {"password": "literal-pass-abc123"}})
    assert resolved["auth"]["password"] == "literal-pass-abc123"
    assert resolver.redact_text("password=literal-pass-abc123") == "password=[redacted-secret]"


def test_apply_secret_resolution_preserves_unknown_placeholders(monkeypatch):
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    resolved, _resolver = apply_secret_resolution({"wpscan": {"api_token": "env:DOES_NOT_EXIST"}})
    assert resolved["wpscan"]["api_token"] == "env:DOES_NOT_EXIST"

