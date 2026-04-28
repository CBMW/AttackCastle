from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from time import monotonic
from typing import Any, Callable
from uuid import uuid4

from attackcastle.gui.models import HttpHistoryEntry, now_iso

HTTP_HISTORY_BODY_PREVIEW_BYTES = 256_000


def _headers_to_dict(headers: Any) -> dict[str, str]:
    try:
        return {str(key): str(value) for key, value in headers.items()}
    except AttributeError:
        return {}


def _body_preview(content: bytes | None) -> str:
    if not content:
        return ""
    preview = bytes(content[:HTTP_HISTORY_BODY_PREVIEW_BYTES])
    suffix = "\n\n[Body truncated]" if len(content) > HTTP_HISTORY_BODY_PREVIEW_BYTES else ""
    if b"\x00" in preview:
        return f"[Binary body: {len(content)} bytes]{suffix}"
    return preview.decode("utf-8", errors="replace") + suffix


def _raw_repeater_request(
    *,
    method: str,
    path: str,
    host: str,
    headers: dict[str, str],
    body: bytes | None,
) -> str:
    normalized_headers = dict(headers)
    if not any(key.lower() == "host" for key in normalized_headers):
        normalized_headers["Host"] = host
    lines = [f"{method or 'GET'} {path or '/'} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in normalized_headers.items())
    request = "\n".join(lines) + "\n\n"
    if body:
        request += body[:HTTP_HISTORY_BODY_PREVIEW_BYTES].decode("utf-8", errors="replace")
    return request


def history_entry_from_flow(flow: Any, workspace_id: str) -> HttpHistoryEntry:
    request = flow.request
    response = getattr(flow, "response", None)
    request_headers = _headers_to_dict(getattr(request, "headers", {}))
    response_headers = _headers_to_dict(getattr(response, "headers", {})) if response is not None else {}
    request_body = getattr(request, "raw_content", None) or getattr(request, "content", b"") or b""
    response_body = (
        getattr(response, "raw_content", None) or getattr(response, "content", b"") or b""
        if response is not None
        else b""
    )
    started = float(getattr(request, "timestamp_start", 0.0) or 0.0)
    ended = float(
        getattr(response, "timestamp_end", 0.0)
        or getattr(response, "timestamp_start", 0.0)
        or getattr(request, "timestamp_end", 0.0)
        or started
    )
    host = str(getattr(request, "host", "") or "")
    method = str(getattr(request, "method", "") or "")
    path = str(getattr(request, "path", "") or "/")
    return HttpHistoryEntry(
        history_id=f"http-{uuid4().hex}",
        workspace_id=workspace_id,
        timestamp=now_iso(),
        scheme=str(getattr(request, "scheme", "") or ""),
        host=host,
        port=int(getattr(request, "port", 0) or 0),
        method=method,
        path=path,
        url=str(getattr(request, "pretty_url", "") or getattr(request, "url", "") or ""),
        request_headers=request_headers,
        request_body_preview=_body_preview(request_body),
        response_status=int(getattr(response, "status_code", 0) or 0) if response is not None else 0,
        response_reason=str(getattr(response, "reason", "") or "") if response is not None else "",
        response_headers=response_headers,
        response_body_preview=_body_preview(response_body),
        duration_ms=max(int((ended - started) * 1000), 0) if started else 0,
        size=len(response_body or b""),
        content_type=response_headers.get("Content-Type") or response_headers.get("content-type") or "",
        tls=str(getattr(request, "scheme", "") or "").lower() == "https",
        error=str(getattr(getattr(flow, "error", None), "msg", "") or ""),
        raw_repeater_request=_raw_repeater_request(
            method=method,
            path=path,
            host=host,
            headers=request_headers,
            body=request_body,
        ),
    )


class _HistoryAddon:
    def __init__(self, workspace_id_provider: Callable[[], str], on_entry: Callable[[HttpHistoryEntry], None]) -> None:
        self._workspace_id_provider = workspace_id_provider
        self._on_entry = on_entry
        self._started_at: dict[str, float] = {}

    def request(self, flow: Any) -> None:
        self._started_at[str(id(flow))] = monotonic()

    def response(self, flow: Any) -> None:
        self._emit(flow)

    def error(self, flow: Any) -> None:
        self._emit(flow)

    def _emit(self, flow: Any) -> None:
        entry = history_entry_from_flow(flow, self._workspace_id_provider())
        started_at = self._started_at.pop(str(id(flow)), None)
        if started_at is not None and entry.duration_ms == 0:
            entry.duration_ms = max(int((monotonic() - started_at) * 1000), 0)
        self._on_entry(entry)


class HttpHistoryProxyService:
    def __init__(
        self,
        *,
        confdir: Path,
        workspace_id_provider: Callable[[], str],
        on_entry: Callable[[HttpHistoryEntry], None],
    ) -> None:
        self._confdir = Path(confdir)
        self._workspace_id_provider = workspace_id_provider
        self._on_entry = on_entry
        self._thread: threading.Thread | None = None
        self._master: Any = None
        self._lock = threading.Lock()
        self._error = ""

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def last_error(self) -> str:
        return self._error

    def ca_cert_path(self) -> Path:
        return self._confdir / "mitmproxy-ca-cert.pem"

    def start(self, host: str, port: int) -> None:
        self.stop()
        try:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster
        except ImportError as exc:
            self._error = f"mitmproxy is not installed: {exc}"
            return

        self._confdir.mkdir(parents=True, exist_ok=True)
        self._error = ""

        async def run_proxy() -> None:
            options = Options(
                listen_host=str(host or "127.0.0.1"),
                listen_port=int(port or 8087),
                confdir=str(self._confdir),
            )
            master = DumpMaster(options, with_termlog=False, with_dumper=False)
            master.addons.add(_HistoryAddon(self._workspace_id_provider, self._on_entry))
            with self._lock:
                self._master = master
            try:
                await master.run()
            except Exception as exc:  # pragma: no cover - depends on mitmproxy runtime internals.
                self._error = str(exc)
            finally:
                with self._lock:
                    if self._master is master:
                        self._master = None

        def thread_main() -> None:
            asyncio.run(run_proxy())

        self._thread = threading.Thread(target=thread_main, name="AttackCastleHttpHistoryProxy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._lock:
            master = self._master
        if master is not None:
            master.shutdown()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
        self._thread = None
