from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from attackcastle.gui.models import now_iso


@dataclass(slots=True)
class GeoRecord:
    ip_address: str
    latitude: float | None = None
    longitude: float | None = None
    country: str = ""
    country_iso_code: str = ""
    region: str = ""
    region_code: str = ""
    city: str = ""
    accuracy_radius_km: int | None = None
    asn: int | None = None
    asn_org: str = ""
    geo_source: str = ""
    geo_confidence: float = 0.0
    geo_last_updated: str = field(default_factory=now_iso)
    lookup_status: str = "unknown"
    lookup_note: str = ""
    network: str = ""
    is_hosting_provider: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GeoRecord":
        return cls(
            ip_address=str(payload.get("ip_address", "")).strip(),
            latitude=float(payload["latitude"]) if payload.get("latitude") is not None else None,
            longitude=float(payload["longitude"]) if payload.get("longitude") is not None else None,
            country=str(payload.get("country", "")),
            country_iso_code=str(payload.get("country_iso_code", "")),
            region=str(payload.get("region", "")),
            region_code=str(payload.get("region_code", "")),
            city=str(payload.get("city", "")),
            accuracy_radius_km=int(payload["accuracy_radius_km"]) if payload.get("accuracy_radius_km") is not None else None,
            asn=int(payload["asn"]) if payload.get("asn") is not None else None,
            asn_org=str(payload.get("asn_org", "")),
            geo_source=str(payload.get("geo_source", "")),
            geo_confidence=float(payload.get("geo_confidence", 0.0) or 0.0),
            geo_last_updated=str(payload.get("geo_last_updated", now_iso())),
            lookup_status=str(payload.get("lookup_status", "unknown")),
            lookup_note=str(payload.get("lookup_note", "")),
            network=str(payload.get("network", "")),
            is_hosting_provider=bool(payload.get("is_hosting_provider", False)),
        )

    def is_usable(self) -> bool:
        return self.lookup_status == "ok" and self.latitude is not None and self.longitude is not None

    def confidence_bucket(self) -> str:
        if self.geo_confidence >= 0.8:
            return "high"
        if self.geo_confidence >= 0.45:
            return "medium"
        return "low"

    def location_label(self) -> str:
        parts = [self.city, self.region, self.country]
        return ", ".join(part for part in parts if part) or self.country_iso_code or self.ip_address


@dataclass(slots=True)
class HeatMapPoint:
    location_key: str
    latitude: float
    longitude: float
    country: str = ""
    region: str = ""
    city: str = ""
    asset_count: int = 0
    ip_count: int = 0
    asset_ids: list[str] = field(default_factory=list)
    sample_asset_labels: list[str] = field(default_factory=list)
    confidence_bucket: str = "low"
    provider_labels: list[str] = field(default_factory=list)
    lookup_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
