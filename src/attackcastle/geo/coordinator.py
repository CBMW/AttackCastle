from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from attackcastle.geo.cache import GeoCache
from attackcastle.geo.models import GeoRecord
from attackcastle.geo.provider import GeoProvider


class _GeoLookupRunnableSignals(QObject):
    finished = Signal(int, list)


class _GeoLookupRunnable(QRunnable):
    def __init__(self, request_id: int, provider: GeoProvider, ip_addresses: list[str]) -> None:
        super().__init__()
        self.request_id = request_id
        self.provider = provider
        self.ip_addresses = list(ip_addresses)
        self.signals = _GeoLookupRunnableSignals()

    def run(self) -> None:
        records = [self.provider.lookup(ip_address).to_dict() for ip_address in self.ip_addresses]
        self.signals.finished.emit(self.request_id, records)


class GeoLookupCoordinator(QObject):
    recordsUpdated = Signal(int, list)
    requestStatusChanged = Signal(int, dict)
    requestCompleted = Signal(int, dict)

    def __init__(
        self,
        provider: GeoProvider,
        cache: GeoCache | None = None,
        *,
        thread_pool: QThreadPool | None = None,
        batch_size: int = 32,
    ) -> None:
        super().__init__()
        self.provider = provider
        self.cache = cache or GeoCache()
        self.thread_pool = thread_pool or QThreadPool.globalInstance()
        self.batch_size = max(int(batch_size), 1)
        self._next_request_id = 1
        self._request_state: dict[int, dict[str, int]] = {}

    def ensure_records(self, ip_addresses: Iterable[str], *, force_refresh: bool = False) -> int:
        request_id = self._next_request_id
        self._next_request_id += 1
        normalized = self._normalize_ip_addresses(ip_addresses)
        immediate_records: list[GeoRecord] = []
        missing: list[str] = []
        for ip_address in normalized:
            immediate = self._classify_non_public(ip_address)
            if immediate is not None:
                immediate_records.append(immediate)
                if not force_refresh:
                    self.cache.set(immediate)
                continue
            cached = None if force_refresh else self.cache.get(ip_address)
            if cached is not None:
                immediate_records.append(cached)
            else:
                missing.append(ip_address)

        self._request_state[request_id] = {
            "total": len(normalized),
            "completed": len(immediate_records),
            "missing": len(missing),
            "batches_outstanding": 0,
        }
        if immediate_records:
            self.recordsUpdated.emit(request_id, [record.to_dict() for record in immediate_records])
        self.requestStatusChanged.emit(request_id, dict(self._request_state[request_id]))

        if not missing:
            self.requestCompleted.emit(request_id, dict(self._request_state[request_id]))
            return request_id

        batches = [missing[index : index + self.batch_size] for index in range(0, len(missing), self.batch_size)]
        self._request_state[request_id]["batches_outstanding"] = len(batches)
        for batch in batches:
            runnable = _GeoLookupRunnable(request_id, self.provider, batch)
            runnable.signals.finished.connect(self._handle_batch_finished)
            self.thread_pool.start(runnable)
        return request_id

    def _handle_batch_finished(self, request_id: int, rows: list[dict]) -> None:
        state = self._request_state.get(request_id)
        if state is None:
            return
        records: list[GeoRecord] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            record = GeoRecord.from_dict(row)
            records.append(record)
            self.cache.set(record)
        if records:
            self.recordsUpdated.emit(request_id, [record.to_dict() for record in records])
        state["completed"] += len(records)
        state["batches_outstanding"] = max(state["batches_outstanding"] - 1, 0)
        self.requestStatusChanged.emit(request_id, dict(state))
        if state["batches_outstanding"] <= 0:
            self.requestCompleted.emit(request_id, dict(state))
            self._request_state.pop(request_id, None)

    @staticmethod
    def _normalize_ip_addresses(ip_addresses: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        normalized: list[str] = []
        for raw in ip_addresses:
            ip_address = str(raw or "").strip()
            if not ip_address or ip_address in seen:
                continue
            seen.add(ip_address)
            normalized.append(ip_address)
        return normalized

    @staticmethod
    def _classify_non_public(ip_address: str) -> GeoRecord | None:
        try:
            parsed = ipaddress.ip_address(ip_address)
        except ValueError:
            return GeoRecord(
                ip_address=ip_address,
                lookup_status="invalid",
                lookup_note="Invalid IP address.",
                geo_source="classifier",
            )
        if parsed.is_global:
            return None
        if parsed.is_private:
            status = "private"
        elif parsed.is_loopback:
            status = "loopback"
        elif parsed.is_link_local:
            status = "link_local"
        elif parsed.is_multicast:
            status = "multicast"
        elif parsed.is_reserved:
            status = "reserved"
        else:
            status = "non_public"
        return GeoRecord(
            ip_address=ip_address,
            lookup_status=status,
            lookup_note="Non-public IP addresses are excluded from geolocation.",
            geo_source="classifier",
        )
