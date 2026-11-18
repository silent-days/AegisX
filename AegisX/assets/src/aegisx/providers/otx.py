"""
AegisX — AlienVault OTX adapter.

Pulse-based threat intelligence across IP, domain and URL indicators.
Requires a free OTX API key: https://otx.alienvault.com
"""

from __future__ import annotations

import requests

from ..utils.validators import TYPE_DOMAIN, TYPE_IP, TYPE_IP6, TYPE_URL, NormalizedIndicator
from .base import ProviderAdapter, finding, severity_from_score

BASE = "https://otx.alienvault.com/api/v1"


class OTXProvider(ProviderAdapter):
    name = "otx"
    display_name = "AlienVault OTX"
    requires_key = True
    description = (
        "Open Threat Exchange pulses: community-curated indicator collections "
        "with adversary infrastructure context, tags and threat types."
    )
    capabilities = ("pulse-intelligence", "ip-reputation", "domain-intelligence",
                    "url-intelligence", "geo", "asn")
    docs_url = "https://otx.alienvault.com/api"
    key_url = "https://otx.alienvault.com/settings/api"
    default_ttl = 6 * 3600
    min_interval = 1.2
    test_url = f"{BASE}/indicators/IPv4/192.0.2.1/general"
    test_headers = {"X-OTX-API-KEY": "check-at-runtime"}

    def _endpoint(self, norm: NormalizedIndicator) -> str:
        if norm.type == TYPE_IP:
            # OTX uses the literal indicator families "IPv4"/"IPv6".
            return f"{BASE}/indicators/IPv4/{norm.value}/general"
        if norm.type == TYPE_IP6:
            return f"{BASE}/indicators/IPv6/{norm.value}/general"
        if norm.type == TYPE_DOMAIN:
            return f"{BASE}/indicators/domain/{norm.value}/general"
        if norm.type == TYPE_URL:
            import hashlib

            url_hash = hashlib.sha1(norm.value.encode()).hexdigest()
            return f"{BASE}/indicators/url/{url_hash}/general"
        return ""

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP, TYPE_IP6, TYPE_DOMAIN, TYPE_URL)

    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        url = self._endpoint(norm)
        if not url:
            return []
        resp = self.http("GET", url, headers={"X-OTX-API-KEY": self.api_key()})
        payload = self._decode(resp)

        pulse_info = (payload or {}).get("pulse_info", {}) or {}
        pulses = pulse_info.get("pulses", []) or []
        count = int(pulse_info.get("count") or len(pulses))
        tags: list[str] = []
        adversary = ""
        for pulse in pulses[:40]:
            tags += [t for t in (pulse.get("tags") or []) if t]
            if pulse.get("adversary") and not adversary:
                adversary = pulse.get("adversary")
        tags = sorted(set(tags))[:12]

        # Score model: pulse count + threat-type votes
        type_votes = {}
        for ptype in pulse_info.get("type_stats", []) or []:
            try:
                type_votes[ptype.get("type", "")] = int(ptype.get("count", 0))
            except (TypeError, ValueError):
                pass
        score = min(95, 30 + count * 6 + sum(type_votes.values()))
        if count == 0:
            score = 12

        enrichment = (payload or {})
        geo = enrichment.get("geo", {}) or {}
        asn = enrichment.get("asn", {}) or {}

        summary = (
            f"OTX: indicator appears in {count} pulse(s)."
            + (f" Associated adversary name in pulses: {adversary} (community claim, not attribution)."
               if adversary else "")
        )
        enrich = {
            "country": geo.get("countryname") or geo.get("country") or "",
            "asn": f"AS{asn.get('asn')}" if asn.get("asn") else "",
            "asn_name": asn.get("isp") or "",
        }
        return [
            finding(
                source=self.display_name,
                severity=severity_from_score(score),
                confidence=0.80,
                score=score if count else None,
                summary=summary,
                tags=tags,
                observed_at=(pulses[0].get("modified") or "").split("T")[0] or None if pulses else None,
                data={
                    "pulse_count": count,
                    "pulse_names": [p.get("name") for p in pulses[:6] if p.get("name")],
                    "adversary_mention": adversary,
                    "threat_types": type_votes,
                    "city": geo.get("city") or "",
                    **enrich,
                },
                enrich=enrich,
            )
        ]
