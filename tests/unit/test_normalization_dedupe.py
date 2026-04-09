from attackcastle.core.models import Asset
from attackcastle.normalization.dedupe import dataclass_key, make_key


def test_make_key_normalizes_structured_values_and_none_stably():
    left = make_key({"b": 2, "a": 1}, ["x", 1], None, "value")
    right = make_key({"a": 1, "b": 2}, ["x", 1], None, "value")

    assert left == right
    assert left == '{"a": 1, "b": 2}|["x", 1]||value'


def test_dataclass_key_extracts_requested_fields_in_order():
    asset = Asset(
        asset_id="asset-1",
        kind="host",
        name="example.com",
        ip="203.0.113.10",
        parent_asset_id=None,
    )

    assert dataclass_key(asset, ["kind", "name", "ip", "parent_asset_id"]) == "host|example.com|203.0.113.10|"

