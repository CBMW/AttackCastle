from __future__ import annotations

from attackcastle.core.enums import TargetType
from attackcastle.scope.classifier import classify_target
from attackcastle.scope.compiler import classify_cloud_provider, compile_scope


def test_scope_compiler_expands_asn_into_cidrs(monkeypatch):
    def fake_fetch(*args, **kwargs):  # noqa: ANN002, ANN003
        return ["203.0.113.0/24", "198.51.100.0/24"]

    monkeypatch.setattr("attackcastle.scope.compiler.fetch_asn_prefixes", fake_fetch)
    targets = [classify_target("AS13335")]
    compilation = compile_scope(
        targets,
        config={"scope": {"enable_asn_expansion": True}},
    )
    assert len(compilation.targets) == 2
    assert all(item.target_type == TargetType.CIDR for item in compilation.targets)
    assert compilation.graph["summary"]["asn_expansion_count"] == 2


def test_scope_compiler_tracks_cloud_hosts():
    targets = [classify_target("https://example.cloudfront.net/login")]
    compilation = compile_scope(targets, config={})
    assert compilation.graph["summary"]["cloud_host_count"] == 1
    providers = {item["provider"] for item in compilation.graph["cloud_hosts"]}
    assert providers == {"aws"}
    assert classify_cloud_provider("app.azurewebsites.net") == "azure"

