from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from attackcastle.geo.models import GeoRecord
from attackcastle.gui.models import now_iso
from attackcastle.storage.cache import FileCache


def default_geo_cache_dir() -> Path:
    return Path.home() / ".attackcastle" / "cache" / "geoip"


class GeoCache:
    def __init__(self, cache_dir: Path | None = None, *, max_age_days: int = 30) -> None:
        self.cache_dir = cache_dir or default_geo_cache_dir()
        self.max_age_days = max(int(max_age_days), 1)
        self._file_cache = FileCache(self.cache_dir)

    def get(self, ip_address: str) -> GeoRecord | None:
        payload = self._file_cache.get(self._key(ip_address))
        if not isinstance(payload, dict):
            return None
        record = GeoRecord.from_dict(payload)
        if self._is_stale(record):
            return None
        return record

    def set(self, record: GeoRecord) -> Path:
        if not record.geo_last_updated:
            record.geo_last_updated = now_iso()
        return self._file_cache.set(self._key(record.ip_address), record.to_dict())

    def delete(self, ip_address: str) -> None:
        path = self._file_cache._path_for_key(self._key(ip_address))
        path.unlink(missing_ok=True)

    @staticmethod
    def _key(ip_address: str) -> str:
        return str(ip_address or "").strip()

    def _is_stale(self, record: GeoRecord) -> bool:
        raw = str(record.geo_last_updated or "").strip()
        if not raw:
            return True
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return True
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed < datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
