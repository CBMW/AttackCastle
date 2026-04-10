from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from attackcastle.geo.models import GeoRecord, HeatMapPoint


@dataclass(slots=True)
class HeatMapAggregationResult:
    points: list[HeatMapPoint]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "points": [point.to_dict() for point in self.points],
            "summary": dict(self.summary),
        }


class HeatMapDataAggregator:
    def build(
        self,
        asset_rows: list[dict[str, Any]],
        geo_records_by_ip: dict[str, GeoRecord],
        *,
        public_only: bool = True,
        asset_kind: str = "all",
        service_filter: str = "all",
    ) -> HeatMapAggregationResult:
        grouped: dict[str, dict[str, Any]] = {}
        total_assets = 0
        assets_with_public_ips = 0
        assets_geolocated = 0
        skipped_private_ips = 0
        unresolved_public_ips = 0
        unique_public_ips: set[str] = set()

        for asset_row in asset_rows:
            if not self._asset_matches_filters(asset_row, asset_kind=asset_kind, service_filter=service_filter):
                continue
            total_assets += 1
            asset_id = str(asset_row.get("asset_id") or "")
            asset_label = str(asset_row.get("__label") or asset_row.get("name") or asset_id or "Asset")
            candidate_ips = self._asset_ips(asset_row)
            public_ip_present = False
            geolocated_here = False
            for ip_address in candidate_ips:
                record = geo_records_by_ip.get(ip_address)
                if record is None:
                    unresolved_public_ips += 1
                    continue
                if record.lookup_status not in {"ok", "partial"}:
                    if record.lookup_status in {"private", "loopback", "reserved", "link_local", "multicast", "non_public"}:
                        skipped_private_ips += 1
                    elif public_only:
                        unresolved_public_ips += 1
                    continue
                public_ip_present = True
                unique_public_ips.add(ip_address)
                if not record.is_usable():
                    unresolved_public_ips += 1
                    continue
                geolocated_here = True
                location_key = self._location_key(record)
                bucket = grouped.setdefault(
                    location_key,
                    {
                        "record": record,
                        "asset_ids": set(),
                        "asset_labels": [],
                        "ip_addresses": set(),
                        "provider_labels": set(),
                        "lookup_notes": set(),
                        "confidence_values": [],
                    },
                )
                bucket["asset_ids"].add(asset_id)
                bucket["ip_addresses"].add(ip_address)
                bucket["confidence_values"].append(record.geo_confidence)
                if asset_label not in bucket["asset_labels"]:
                    bucket["asset_labels"].append(asset_label)
                if record.asn_org:
                    bucket["provider_labels"].add(record.asn_org)
                if record.lookup_note:
                    bucket["lookup_notes"].add(record.lookup_note)
            if public_ip_present:
                assets_with_public_ips += 1
            if geolocated_here:
                assets_geolocated += 1

        points: list[HeatMapPoint] = []
        for location_key, bucket in grouped.items():
            record = bucket["record"]
            confidence_value = max(bucket["confidence_values"] or [record.geo_confidence])
            confidence_bucket = "high" if confidence_value >= 0.8 else "medium" if confidence_value >= 0.45 else "low"
            points.append(
                HeatMapPoint(
                    location_key=location_key,
                    latitude=float(record.latitude),
                    longitude=float(record.longitude),
                    country=record.country,
                    region=record.region,
                    city=record.city,
                    asset_count=len(bucket["asset_ids"]),
                    ip_count=len(bucket["ip_addresses"]),
                    asset_ids=sorted(bucket["asset_ids"]),
                    sample_asset_labels=bucket["asset_labels"][:6],
                    confidence_bucket=confidence_bucket,
                    provider_labels=sorted(bucket["provider_labels"])[:4],
                    lookup_notes=sorted(bucket["lookup_notes"])[:4],
                )
            )
        points.sort(key=lambda item: (-item.asset_count, -item.ip_count, item.country, item.region, item.city))
        return HeatMapAggregationResult(
            points=points,
            summary={
                "asset_count": total_assets,
                "assets_with_public_ips": assets_with_public_ips,
                "geolocated_asset_count": assets_geolocated,
                "location_count": len(points),
                "public_ip_count": len(unique_public_ips),
                "unresolved_public_ip_count": unresolved_public_ips,
                "skipped_private_ip_count": skipped_private_ips,
                "empty_reason": self._empty_reason(total_assets, points, assets_with_public_ips, unresolved_public_ips),
            },
        )

    @staticmethod
    def _asset_ips(asset_row: dict[str, Any]) -> list[str]:
        values = [str(asset_row.get("ip") or "").strip()]
        values.extend(str(item).strip() for item in asset_row.get("resolved_ips") or [])
        unique: list[str] = []
        seen: set[str] = set()
        for ip_address in values:
            if not ip_address or ip_address in seen:
                continue
            seen.add(ip_address)
            unique.append(ip_address)
        return unique

    @staticmethod
    def _asset_matches_filters(asset_row: dict[str, Any], *, asset_kind: str, service_filter: str) -> bool:
        if asset_kind not in {"", "all"} and str(asset_row.get("kind") or "").strip().lower() != asset_kind:
            return False
        service_count = int(asset_row.get("__service_count") or 0)
        web_count = int(asset_row.get("__web_count") or 0)
        if service_filter == "services" and service_count <= 0:
            return False
        if service_filter == "web" and web_count <= 0:
            return False
        return True

    @staticmethod
    def _location_key(record: GeoRecord) -> str:
        latitude = round(float(record.latitude or 0.0), 2)
        longitude = round(float(record.longitude or 0.0), 2)
        city = str(record.city or "").strip().lower()
        region = str(record.region_code or record.region or "").strip().lower()
        country = str(record.country_iso_code or record.country or "").strip().lower()
        return "|".join((country, region, city, f"{latitude:.2f}", f"{longitude:.2f}"))

    @staticmethod
    def _empty_reason(
        asset_count: int,
        points: list[HeatMapPoint],
        assets_with_public_ips: int,
        unresolved_public_ip_count: int,
    ) -> str:
        if asset_count <= 0:
            return "No assets match the current search or map filters."
        if assets_with_public_ips <= 0:
            return "No public IPs were found for the visible assets."
        if not points and unresolved_public_ip_count > 0:
            return "Public IPs were found, but geolocation data is unavailable or incomplete."
        if not points:
            return "No geolocated hotspots are available for the visible assets."
        return ""
