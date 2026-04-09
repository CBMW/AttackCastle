from __future__ import annotations

from attackcastle.policy.risk import resolve_risk_mode


def test_resolve_risk_mode_uses_profile_mapping():
    mode, controls = resolve_risk_mode(
        profile_name="cautious",
        config={"risk_modes": {"mode_by_profile": {"cautious": "passive"}}},
    )
    assert mode == "passive"
    assert controls["allow_sqlmap"] is False


def test_resolve_risk_mode_allows_explicit_override():
    mode, controls = resolve_risk_mode(
        profile_name="cautious",
        config={"risk_modes": {"mode_by_profile": {"cautious": "passive"}}},
        requested_mode="aggressive",
    )
    assert mode == "aggressive"
    assert controls["allow_sqlmap"] is True

