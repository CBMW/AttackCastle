from __future__ import annotations

import ipaddress
from pathlib import Path

from attackcastle.geo.models import GeoRecord
from attackcastle.geo.provider import GeoProvider

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # pragma: no cover - dependency optional at runtime.
    geoip2 = None


_HOSTING_TOKENS = (
    "amazon",
    "aws",
    "akamai",
    "azure",
    "cloud",
    "cloudflare",
    "digitalocean",
    "fastly",
    "google",
    "gcp",
    "hetzner",
    "linode",
    "microsoft",
    "oracle",
    "ovh",
    "vercel",
)


class MaxMindGeoProvider(GeoProvider):
    def __init__(self, city_db_path: Path | None = None, asn_db_path: Path | None = None) -> None:
        self.city_db_path = city_db_path or self._detect_database(
            env_keys=("ATTACKCASTLE_GEOLITE_CITY_DB", "GEOLITE2_CITY_DB"),
            file_names=("GeoLite2-City.mmdb", "GeoIP2-City.mmdb"),
        )
        self.asn_db_path = asn_db_path or self._detect_database(
            env_keys=("ATTACKCASTLE_GEOLITE_ASN_DB", "GEOLITE2_ASN_DB"),
            file_names=("GeoLite2-ASN.mmdb", "GeoIP2-ASN.mmdb"),
        )
        self._city_reader = None
        self._asn_reader = None

    @property
    def available(self) -> bool:
        return geoip2 is not None and self.city_db_path is not None and self.city_db_path.exists()

    def lookup(self, ip_address: str) -> GeoRecord:
        normalized = str(ip_address or "").strip()
        try:
            parsed_ip = ipaddress.ip_address(normalized)
        except ValueError:
            return GeoRecord(
                ip_address=normalized,
                lookup_status="invalid",
                lookup_note="Invalid IP address.",
                geo_source="maxmind",
            )
        if not parsed_ip.is_global:
            return GeoRecord(
                ip_address=normalized,
                lookup_status=self._non_public_status(parsed_ip),
                lookup_note="Non-public IP addresses are excluded from geolocation.",
                geo_source="maxmind",
            )
        if geoip2 is None:
            return GeoRecord(
                ip_address=normalized,
                lookup_status="missing_dependency",
                lookup_note="The geoip2 Python package is not installed.",
                geo_source="maxmind",
            )
        if self.city_db_path is None or not self.city_db_path.exists():
            return GeoRecord(
                ip_address=normalized,
                lookup_status="missing_db",
                lookup_note="GeoLite2 City database was not found.",
                geo_source="maxmind",
            )

        city_response = self._city_lookup(normalized)
        if isinstance(city_response, GeoRecord):
            return city_response

        country = str(city_response.country.name or "")
        country_iso = str(city_response.country.iso_code or "")
        subdivisions = list(getattr(city_response.subdivisions, "_records", []) or [])
        region = str(subdivisions[0].name or "") if subdivisions else ""
        region_code = str(subdivisions[0].iso_code or "") if subdivisions else ""
        city = str(city_response.city.name or "")
        latitude = city_response.location.latitude
        longitude = city_response.location.longitude
        accuracy_radius = city_response.location.accuracy_radius
        network = str(city_response.traits.network or "") if getattr(city_response, "traits", None) is not None else ""

        asn = None
        asn_org = ""
        if self.asn_db_path is not None and self.asn_db_path.exists():
            try:
                asn_response = self._asn_reader_instance().asn(normalized)
                asn = int(asn_response.autonomous_system_number) if asn_response.autonomous_system_number is not None else None
                asn_org = str(asn_response.autonomous_system_organization or "")
                if not network:
                    network = str(asn_response.network or "")
            except Exception:
                pass

        confidence = self._confidence(
            latitude=latitude,
            longitude=longitude,
            country=country,
            region=region,
            city=city,
            accuracy_radius_km=accuracy_radius,
            asn_org=asn_org,
        )
        is_hosting_provider = self._is_hosting_provider(asn_org)
        if is_hosting_provider:
            confidence = min(confidence, 0.45)

        note_parts: list[str] = []
        if accuracy_radius is not None:
            note_parts.append(f"Approximate within {accuracy_radius} km")
        if is_hosting_provider:
            note_parts.append("Likely infrastructure/provider location")

        return GeoRecord(
            ip_address=normalized,
            latitude=latitude,
            longitude=longitude,
            country=country,
            country_iso_code=country_iso,
            region=region,
            region_code=region_code,
            city=city,
            accuracy_radius_km=int(accuracy_radius) if accuracy_radius is not None else None,
            asn=asn,
            asn_org=asn_org,
            geo_source="maxmind_geolite2",
            geo_confidence=confidence,
            lookup_status="ok" if latitude is not None and longitude is not None else "partial",
            lookup_note=". ".join(note_parts),
            network=network,
            is_hosting_provider=is_hosting_provider,
        )

    def _city_lookup(self, ip_address: str):
        try:
            return self._city_reader_instance().city(ip_address)
        except geoip2.errors.AddressNotFoundError:
            return GeoRecord(
                ip_address=ip_address,
                lookup_status="not_found",
                lookup_note="No GeoLite2 city record matched this IP.",
                geo_source="maxmind",
            )
        except Exception as exc:
            return GeoRecord(
                ip_address=ip_address,
                lookup_status="lookup_error",
                lookup_note=str(exc),
                geo_source="maxmind",
            )

    def _city_reader_instance(self):
        if self._city_reader is None:
            self._city_reader = geoip2.database.Reader(str(self.city_db_path))
        return self._city_reader

    def _asn_reader_instance(self):
        if self._asn_reader is None:
            self._asn_reader = geoip2.database.Reader(str(self.asn_db_path))
        return self._asn_reader

    @staticmethod
    def _detect_database(*, env_keys: tuple[str, ...], file_names: tuple[str, ...]) -> Path | None:
        import os

        for env_key in env_keys:
            candidate = str(os.environ.get(env_key, "")).strip()
            if candidate:
                path = Path(candidate).expanduser()
                if path.exists():
                    return path
        candidate_dirs = (
            Path.home() / ".attackcastle" / "geoip",
            Path.home() / ".local" / "share" / "GeoIP",
            Path("/usr/share/GeoIP"),
            Path("/usr/local/share/GeoIP"),
            Path("/var/lib/GeoIP"),
        )
        for directory in candidate_dirs:
            for file_name in file_names:
                candidate = directory / file_name
                if candidate.exists():
                    return candidate
        return None

    @staticmethod
    def _non_public_status(parsed_ip: ipaddress._BaseAddress) -> str:
        if parsed_ip.is_private:
            return "private"
        if parsed_ip.is_loopback:
            return "loopback"
        if parsed_ip.is_link_local:
            return "link_local"
        if parsed_ip.is_multicast:
            return "multicast"
        if parsed_ip.is_reserved:
            return "reserved"
        return "non_public"

    @staticmethod
    def _is_hosting_provider(asn_org: str) -> bool:
        normalized = str(asn_org or "").strip().lower()
        return any(token in normalized for token in _HOSTING_TOKENS)

    @classmethod
    def _confidence(
        cls,
        *,
        latitude: float | None,
        longitude: float | None,
        country: str,
        region: str,
        city: str,
        accuracy_radius_km: int | None,
        asn_org: str,
    ) -> float:
        if latitude is None or longitude is None:
            return 0.0
        score = 0.35
        if country:
            score += 0.15
        if region:
            score += 0.15
        if city:
            score += 0.15
        if accuracy_radius_km is not None:
            if accuracy_radius_km <= 50:
                score += 0.2
            elif accuracy_radius_km <= 250:
                score += 0.1
            elif accuracy_radius_km >= 800:
                score -= 0.1
        if cls._is_hosting_provider(asn_org):
            score -= 0.2
        return max(0.0, min(score, 1.0))
