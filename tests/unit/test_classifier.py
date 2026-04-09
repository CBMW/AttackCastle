from attackcastle.core.enums import TargetType
from attackcastle.scope.classifier import classify_target


def test_classify_single_ip():
    target = classify_target("192.168.1.10")
    assert target.target_type == TargetType.SINGLE_IP


def test_classify_cidr():
    target = classify_target("10.0.0.0/24")
    assert target.target_type == TargetType.CIDR


def test_classify_domain():
    target = classify_target("example.com")
    assert target.target_type == TargetType.DOMAIN


def test_classify_wildcard_domain():
    target = classify_target("*.example.com")
    assert target.target_type == TargetType.WILDCARD_DOMAIN


def test_classify_url():
    target = classify_target("https://example.com/login")
    assert target.target_type == TargetType.URL
    assert target.host == "example.com"


def test_classify_wildcard_url_normalizes_host():
    target = classify_target("https://*.example.com/")
    assert target.target_type == TargetType.URL
    assert target.host == "example.com"


def test_classify_host_port():
    target = classify_target("api.example.com:8443")
    assert target.target_type == TargetType.HOST_PORT
    assert target.port == 8443


def test_classify_forced_wildcard_domain():
    target = classify_target("example.com", forced_type="wildcard_domain")
    assert target.target_type == TargetType.WILDCARD_DOMAIN
    assert target.value == "*.example.com"
    assert target.host == "example.com"
