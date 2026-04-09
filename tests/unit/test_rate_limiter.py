from __future__ import annotations

from attackcastle.orchestration.rate_limiter import AdaptiveRateLimiter


def test_rate_limiter_adaptive_backoff_state_increases_on_failures():
    limiter = AdaptiveRateLimiter(
        {
            "per_target_min_interval_ms": 0,
            "per_service_min_interval_ms": 0,
            "adaptive_backoff_enabled": True,
            "adaptive_base_backoff_ms": 1,
            "adaptive_multiplier": 2.0,
            "adaptive_max_backoff_ms": 8,
            "failure_threshold": 1,
        }
    )
    limiter.record(target_key="http://example.com", success=False)
    limiter.record(target_key="http://example.com", success=False)
    snapshot = limiter.snapshot()
    state = snapshot["adaptive_state"]["http://example.com"]
    assert state["failures"] >= 2
    assert state["backoff_ms"] >= 2


def test_rate_limiter_reduces_backoff_after_success():
    limiter = AdaptiveRateLimiter(
        {
            "adaptive_backoff_enabled": True,
            "adaptive_base_backoff_ms": 4,
            "adaptive_multiplier": 2.0,
            "adaptive_max_backoff_ms": 16,
            "failure_threshold": 1,
        }
    )
    limiter.record(target_key="service:1", success=False)
    before = limiter.snapshot()["adaptive_state"]["service:1"]["backoff_ms"]
    limiter.record(target_key="service:1", success=True)
    after = limiter.snapshot()["adaptive_state"]["service:1"]["backoff_ms"]
    assert after <= before


def test_rate_limiter_downgrades_after_noisy_canary():
    limiter = AdaptiveRateLimiter(
        {
            "adaptive_backoff_enabled": True,
            "adaptive_base_backoff_ms": 1,
            "failure_threshold": 1,
            "downgrade_after_canary_failures": 1,
        }
    )
    limiter.record(
        target_key="https://portal.example.com",
        success=False,
        status_code=403,
        noisy_hint=True,
        canary=True,
        generic_response=True,
    )
    snapshot = limiter.snapshot()
    state = snapshot["adaptive_state"]["https://portal.example.com"]
    assert state["mode"] in {"balanced", "careful"}
    assert state["canary_failures"] >= 1
