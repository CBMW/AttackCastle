from attackcastle.reporting.audience import is_consultant_audience, normalize_report_audience


def test_normalize_report_audience_defaults_to_consultant():
    assert normalize_report_audience(None) == "consultant"
    assert normalize_report_audience("   ") == "consultant"
    assert normalize_report_audience("unknown") == "consultant"


def test_normalize_report_audience_accepts_aliases_and_canonical_values():
    assert normalize_report_audience("technical") == "consultant"
    assert normalize_report_audience("client-safe") == "client"
    assert normalize_report_audience("Executive") == "executive"
    assert normalize_report_audience("consultant") == "consultant"


def test_is_consultant_audience_resolves_aliases():
    assert is_consultant_audience("technical") is True
    assert is_consultant_audience("consultant") is True
    assert is_consultant_audience("client") is False

