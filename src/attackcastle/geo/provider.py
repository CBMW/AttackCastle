from __future__ import annotations

from typing import Protocol

from attackcastle.geo.models import GeoRecord


class GeoProvider(Protocol):
    def lookup(self, ip_address: str) -> GeoRecord:
        raise NotImplementedError
