from __future__ import annotations

from types import SimpleNamespace

from attackcastle.gui.http_history_proxy import history_entry_from_flow


def test_history_entry_from_flow_builds_repeater_request_and_response_metadata() -> None:
    flow = SimpleNamespace(
        request=SimpleNamespace(
            scheme="http",
            host="127.0.0.1",
            port=8080,
            method="POST",
            path="/submit",
            pretty_url="http://127.0.0.1:8080/submit",
            headers={"Content-Type": "text/plain"},
            raw_content=b"ping",
            timestamp_start=10.0,
        ),
        response=SimpleNamespace(
            status_code=202,
            reason="Accepted",
            headers={"Content-Type": "text/plain"},
            raw_content=b"seen:ping",
            timestamp_end=10.125,
        ),
        error=None,
    )

    entry = history_entry_from_flow(flow, "workspace-1")

    assert entry.workspace_id == "workspace-1"
    assert entry.method == "POST"
    assert entry.response_status == 202
    assert entry.duration_ms == 125
    assert entry.response_body_preview == "seen:ping"
    assert entry.raw_repeater_request == "POST /submit HTTP/1.1\nContent-Type: text/plain\nHost: 127.0.0.1\n\nping"
