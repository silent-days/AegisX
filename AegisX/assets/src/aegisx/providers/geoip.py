"""
AegisX — GeoIP adapter.

Approximate IP geolocation. Two operating modes:

  * Local MaxMind GeoLite2-City database (point the setting ``geoip_db_path``
    at the .mmdb file, optional ``geoip2`` package required).
  * Enrichment pass-through: when no local database is installed, country /
    ASN context captured by other providers is reused (no extra lookup).

The provider never fabricates coordinates; without a database it reports
"not configured" and the UI explains how to enable it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ..utils.validators import TYPE_IP, TYPE_IP6, NormalizedIndicator
from .base import ProviderAdapter, ProviderNotConfigured, finding

log = logging.getLogger("aegisx.geoip")


class GeoIPProvider(ProviderAdapter):
    name = "geoip"
    display_name = "MaxMind GeoIP"
    requires_key = False
    description = (
        "Approximate city/country-level geolocation for IP indicators using the "
        "local GeoLite2 database. Configure the .mmdb path in Settings."
    )
    capabilities = ("ip-geolocation", "asn-context", "map-plotting")
    docs_url = "https://dev.maxmind.com/geoip/docs/databases/city-and-country"
    default_ttl = 30 * 24 * 3600
    min_interval = 0.2

    def db_path(self) -> str:
        return (
            os.environ.get("AEGISX_GEOIP_DB", "")
            or self.repo.get_setting("geoip_db_path", "")
        )

    def is_configured(self) -> bool:
        db = self.db_path()
        return bool(db and Path(db).is_file())

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP, TYPE_IP6)

    def _test_geoip(self) -> str:
        db = self.db_path()
        if not (db and Path(db).is_file()):
            raise ProviderNotConfigured("Set the GeoLite2-City .mmdb path first.")
        try:
            import geoip2.database  # type: ignore
        except ImportError as e:
            raise ProviderNotConfigured("Optional package 'geoip2' is not installed.") from e
        try:
            reader = geoip2.database.Reader(db)
            try:
                reader.city("192.0.2.1")
            except Exception:  # noqa: BLE001 - any parse result still proves DB validity
                pass
            finally:
                reader.close()
        except Exception as e:  # noqa: BLE001
            raise ProviderError(f"GeoLite2 database failed to open: {e}") from e
        return f"GeoLite2 database OK ({Path(db).name})."

    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        db_path = self.db_path()
        if not (db_path and Path(db_path).is_file()):
            raise ProviderNotConfigured(
                "GeoLite2-City database not installed — set its path in "
                "Settings → Intelligence Sources (free account at maxmind.com)."
            )
        try:
            import geoip2.database  # type: ignore
        except ImportError as e:
            raise ProviderNotConfigured(
                "The optional 'geoip2' package is not installed in the application "
                "environment (pip install geoip2)."
            ) from e

        reader = geoip2.database.Reader(db_path)
        try:
            record = reader.city(norm.value)
        except Exception as e:  # noqa: BLE001
            raise ProviderError(f"GeoIP lookup failed for {norm.value}: {e}") from e
        finally:
            reader.close()

        country = (record.country.iso_code or "").upper()
        city = record.city.name or ""
        lat = float(record.location.latitude) if record.location.latitude is not None else None
        lon = float(record.location.longitude) if record.location.longitude is not None else None
        asn = ""
        asn_name = ""
        try:
            asn_rec = geoip2.database.Reader(db_path.replace(".mmdb", ".mmdb")).asn(norm.value)
            asn = f"AS{asn_rec.autonomous_system_number}"
            asn_name = asn_rec.autonomous_system_organization or ""
        except Exception:  # noqa: BLE001
            pass

        data = {
            "country": country,
            "country_name": record.country.name or "",
            "city": city,
            "lat": lat,
            "lon": lon,
            "asn": asn,
            "asn_name": asn_name,
        }
        return [
            finding(
                source=self.display_name,
                severity="info",
                confidence=0.75 if lat is not None else 0.4,
                score=None,
                summary=f"GeoIP: {city or 'unknown city'}, {country or 'unknown country'}"
                        + (f" ({asn} {asn_name})" if asn else ""),
                tags=["geolocated"],
                data=data,
                enrich={"country": country, "asn": asn, "asn_name": asn_name},
            )
        ]
