"""
AegisX — VirusTotal adapter.

Multi-engine verdicts for IP, domain and URL indicators. Requires a free
API key: https://www.virustotal.com/gui/my-apikey
"""

from __future__ import annotations

from ..utils.validators import TYPE_DOMAIN, TYPE_IP, TYPE_IP6, TYPE_URL, NormalizedIndicator
from .base import ProviderAdapter, finding, severity_from_score

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ProviderAdapter):
    name = "virustotal"
    display_name = "VirusTotal"
    requires_key = True
    description = (
        "Aggregated verdicts from ~70 antivirus engines and URL scanners: "
        "detection ratios, engine names, resolution history and popularity."
    )
    capabilities = ("multi-engine-verdicts", "ip-reputation", "domain-intelligence",
                    "url-intelligence", "file-context")
    docs_url = "https://docs.virustotal.com/reference/overview"
    default_ttl = 6 * 3600
    min_interval = 2.5           # public key: 4 req/min
    test_url = f"{BASE}/ip_addresses/192.0.2.1"

    def _endpoint(self, norm: NormalizedIndicator) -> str:
        if norm.type in (TYPE_IP, TYPE_IP6):
            return f"{BASE}/ip_addresses/{norm.value}"
        if norm.type == TYPE_DOMAIN:
            return f"{BASE}/domains/{norm.value}"
        if norm.type == TYPE_URL:
            import base64

            url_id = base64.urlsafe_b64encode(norm.value.encode()).decode().strip("=")
            return f"{BASE}/urls/{url_id}"
        return ""

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP, TYPE_IP6, TYPE_DOMAIN, TYPE_URL)

    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        url = self._endpoint(norm)
        if not url:
            return []
        resp = self.http("GET", url, headers={"x-apikey": self.api_key()})
        payload = self._decode(resp)
        attrs = ((payload or {}).get("data", {}) or {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        results = attrs.get("last_analysis_results", {}) or {}

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        detections = []
        for engine, res in (results or {}).items():
            if res.get("category") in ("malicious", "suspicious") and res.get("result"):
                detections.append(f"{engine}: {res['result']}")
        detections = sorted(set(detections))[:14]

        score = min(100, int((malicious + 0.5 * suspicious) / max(total, 1) * 100 * 2.2)) \
            if total else None
        if malicious == 0 and suspicious == 0 and total:
            score = 5

        tags = list((attrs.get("tags") or []))[:10]
        if malicious >= 5:
            tags.append("multi-engine-detection")

        enrich: dict = {}
        if norm.type in (TYPE_IP, TYPE_IP6):
            enrich["country"] = attrs.get("country") or ""
            asn_field = attrs.get("network") or ""
            if asn_field:
                enrich["asn"] = asn_field.split("/")[-1] if "/" in asn_field else ""
            enrich["asn_name"] = attrs.get("as_owner") or ""

        summary = (
            f"VirusTotal: {malicious}/{total} engines flagged this indicator malicious, "
            f"{suspicious} suspicious."
            + (" No engine flagged it." if total and malicious + suspicious == 0 else "")
        )
        meta = {
            "engines_total": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "detections": detections,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "last_analysis": attrs.get("last_analysis_date"),
        }
        if norm.type == TYPE_DOMAIN:
            meta["resolutions"] = [
                r.get("ip_address")
                for r in (attrs.get("last_dns_records") or [])
                if r.get("type") in ("A", "AAAA")
            ][:8]
        if norm.type in (TYPE_IP, TYPE_IP6):
            meta["as_owner"] = attrs.get("as_owner") or ""
        return [
            finding(
                source=self.display_name,
                severity=severity_from_score(score or 0),
                confidence=0.92,
                score=score,
                summary=summary,
                tags=tags,
                data={**meta, **enrich},
                enrich=enrich,
            )
        ]
