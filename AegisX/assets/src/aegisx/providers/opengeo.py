"""
AegisX — OpenGeo Web adapter (keyless).

Free, keyless IP geolocation and network ownership context:

  * Primary: ipwho.is — JSON geo/ASN lookup with no key and generous limits.
  * Fallback: ip-api.com — classic free endpoint (45 req/min) when ipwho.is
    is unreachable.

Findings carry ``enrich`` metadata (country, ASN, organization, coordinates)
so indicators automatically gain map/country context without any local
MaxMind database or API key.
"""

from __future__ import annotations

import logging

from ..utils.validators import TYPE_IP, TYPE_IP6, NormalizedIndicator
from .base import ProviderAdapter, ProviderError, finding

log = logging.getLogger("aegisx.providers.opengeo")

PRIMARY_URL = "https://ipwho.is/{ip}"
FALLBACK_URL = "http://ip-api.com/json/{ip}"


class OpenGeoProvider(ProviderAdapter):
    name = "opengeo"
    display_name = "OpenGeo Web"
    requires_key = False
    description = (
        "Keyless IP geolocation (ipwho.is with ip-api.com fallback): country, "
        "city, ASN and organization context that enriches indicators for maps "
        "and country analytics — no key needed."
    )
    capabilities = ("ip-geolocation", "asn-context", "map-plotting",
                    "org-context")
    docs_url = "https://ipwho.is/"
    default_ttl = 14 * 24 * 3600
    min_interval = 1.5
    test_url = PRIMARY_URL.format(ip="8.8.8.8")
    test_method = "GET"

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP,)

    # ---------------------------------------------------------------- lookup
    def _primary(self, ip: str) -> dict | None:
        try:
            resp = self.http("GET", PRIMARY_URL.format(ip=ip))
            payload = resp.json()
            if payload.get("success") is False:
                return None
            return payload
        except Exception as e:  # noqa: BLE001
            log.debug("ipwho.is failed for %s: %s", ip, e)
            return None

    def _fallback(self, ip: str) -> dict | None:
        try:
            resp = self.http("GET", FALLBACK_URL.format(ip=ip))
            payload = resp.json()
            if payload.get("status") != "success":
                return None
            return payload
        except Exception as e:  # noqa: BLE001
            log.debug("ip-api.com failed for %s: %s", ip, e)
            return None

    # ----------------------------------------------------------------- fetch
    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        ip = norm.value
        payload = self._primary(ip)
        enriched = {}
        country_code = ""
        notes: list[str] = []

        if payload:
            country_code = payload.get("country_code") or ""
            enriched = {
                "country": country_code,
                "asn": (payload.get("connection") or {}).get("asn"),
                "asn_name": (payload.get("connection") or {}).get("org"),
                "city": payload.get("city"),
                "lat": payload.get("latitude"),
                "lon": payload.get("longitude"),
            }
            notes = [
                f"Located in {payload.get('city') or '—'}, "
                f"{payload.get('country') or '—'}",
            ]
            conn = payload.get("connection") or {}
            if conn.get("org"):
                notes.append(f"network: {conn.get('org')}")
            if conn.get("isp"):
                notes.append(f"ISP: {conn['isp']}")
        else:
            payload = self._fallback(ip)
            if not payload:
                raise ProviderError(
                    "OpenGeo Web: both keyless geo services unreachable")
            country_code = payload.get("countryCode") or ""
            enriched = {
                "country": country_code,
                "asn": f"AS{payload.get('as')}".split()[0]
                       if payload.get("as") else None,
                "asn_name": payload.get("org") or payload.get("as"),
                "city": payload.get("city"),
                "lat": payload.get("lat"),
                "lon": payload.get("lon"),
            }
            notes = [f"Located in {payload.get('city') or '—'}, "
                     f"{payload.get('country') or '—'}",
                     f"network: {payload.get('org') or '—'}"]

        data = dict(enriched)
        data["ip"] = ip
        data["service"] = "ipwho.is" if payload.get("success") is not None else "ip-api.com"
        return [
            finding(
                source=self.display_name,
                severity="info",
                confidence=0.7,
                score=None,
                summary=f"OpenGeo Web: {' · '.join(notes)}.",
                tags=["geo-context"],
                data=data,
                enrich=enriched,
            )
        ]
