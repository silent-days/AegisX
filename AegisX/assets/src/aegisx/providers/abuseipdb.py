"""
AegisX — AbuseIPDB adapter.

IP address abuse intelligence. Requires a free API key:
https://www.abuseipdb.com/account/api
"""

from __future__ import annotations

import requests

from ..utils.validators import NormalizedIndicator, TYPE_IP, TYPE_IP6
from .base import ProviderAdapter, finding, severity_from_score

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(ProviderAdapter):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    requires_key = True
    description = (
        "Community-powered IP abuse reports: confidence-of-abuse score, report "
        "counts, ISP/usage classification and country of origin."
    )
    capabilities = ("ip-reputation", "abuse-reports", "isp-classification", "geo")
    docs_url = "https://www.abuseipdb.com/account/api"
    default_ttl = 6 * 3600
    min_interval = 1.2
    test_url = API_URL
    test_params = {"ipAddress": "192.0.2.1", "maxAgeInDays": 1}

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP, TYPE_IP6)

    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        resp = self.http(
            "GET", API_URL,
            params={"ipAddress": norm.value, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": self.api_key(), "Accept": "application/json"},
        )
        payload = self._decode(resp)
        data = (payload or {}).get("data", {}) or {}

        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        tags = list(data.get("tags") or [])
        if score >= 55:
            tags += ["c2"] if "c2" not in tags else []

        summary = (
            f"AbuseIPDB confidence of abuse: {score}% across {reports} reports "
            f"in the last 90 days."
            + (f" ISP: {data.get('isp')}" if data.get("isp") else "")
            + (f" · Usage: {data.get('usageType')}" if data.get("usageType") else "")
        )
        enrich = {
            "country": data.get("countryCode") or "",
            "asn": f"AS{data.get('asn')}" if data.get("asn") else "",
            "asn_name": data.get("isp") or "",
        }
        return [
            finding(
                source=self.display_name,
                severity=severity_from_score(score),
                confidence=0.88,
                score=score,
                summary=summary,
                tags=[t for t in tags if t],
                observed_at=(data.get("lastReportedAt") or "").split("T")[0] or None,
                data={
                    "reports": reports,
                    "usage_type": data.get("usageType") or "",
                    "isp": data.get("isp") or "",
                    "domain": data.get("domain") or "",
                    "tor": bool(data.get("isTor")),
                    "whitelisted": bool(data.get("isWhitelisted")),
                    "last_reported": data.get("lastReportedAt") or "",
                    **enrich,
                },
                enrich=enrich,
            )
        ]
