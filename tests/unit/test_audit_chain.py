from __future__ import annotations

from attackcastle.logging.audit import AuditLogger, verify_audit_chain


def test_audit_chain_verifies_when_untampered(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)
    logger.write("event.one", {"value": 1})
    logger.write("event.two", {"value": 2})
    result = verify_audit_chain(audit_path)
    assert result["valid"] is True
    assert result["event_count"] == 2
    assert result["format"] == "hashed"


def test_audit_chain_accepts_legacy_unhashed_logs(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    audit_path.write_text(
        '{"timestamp":"2026-03-09T02:21:46.761533+00:00","event_type":"task.started","payload":{"task":"resolve-hosts"}}\n'
        '{"timestamp":"2026-03-09T02:21:46.815639+00:00","event_type":"task.completed","payload":{"task":"resolve-hosts","status":"completed"}}\n',
        encoding="utf-8",
    )
    result = verify_audit_chain(audit_path)
    assert result["valid"] is True
    assert result["format"] == "legacy_unhashed"


def test_audit_chain_detects_tampering(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit_path)
    logger.write("event.one", {"value": 1})
    logger.write("event.two", {"value": 2})
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"value": 2', '"value": 999')
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_audit_chain(audit_path)
    assert result["valid"] is False
    assert result["format"] == "hashed"
    assert result["errors"]
