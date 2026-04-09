from pathlib import Path

from attackcastle.core.enums import Severity
from attackcastle.core.models import RunMetadata, now_utc
from attackcastle.storage.artifacts import ArtifactManager
from attackcastle.storage.cache import FileCache
from attackcastle.storage.run_store import RunStore


def test_file_cache_returns_none_for_missing_key(tmp_path: Path):
    cache = FileCache(tmp_path)

    assert cache.get("missing") is None


def test_file_cache_serializes_dataclasses_enums_and_datetimes(tmp_path: Path):
    cache = FileCache(tmp_path)
    metadata = RunMetadata(
        run_id="cache-test",
        target_input="example.com",
        profile="standard",
        output_dir=str(tmp_path),
        started_at=now_utc(),
    )

    path = cache.set(
        "run:cache-test",
        {
            "metadata": metadata,
            "severity": Severity.HIGH,
            "captured_at": metadata.started_at,
        },
    )

    cached = cache.get("run:cache-test")

    assert path.exists()
    assert cached["metadata"]["run_id"] == "cache-test"
    assert cached["severity"] == "high"
    assert cached["captured_at"] == metadata.started_at.isoformat()


def test_artifact_manager_writes_text_and_bytes_to_raw_artifact_tree(tmp_path: Path):
    run_store = RunStore(output_root=tmp_path, run_id="artifacts")
    manager = ArtifactManager(run_store)

    text_path = manager.write_tool_text("nmap", "stdout.txt", "scan complete")
    bytes_path = manager.write_tool_bytes("nmap", "result.bin", b"\x00\x01attackcastle")

    assert text_path == run_store.artifacts_raw_dir / "nmap" / "stdout.txt"
    assert bytes_path == run_store.artifacts_raw_dir / "nmap" / "result.bin"
    assert text_path.read_text(encoding="utf-8") == "scan complete"
    assert bytes_path.read_bytes() == b"\x00\x01attackcastle"

