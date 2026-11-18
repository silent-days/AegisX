"""
AegisX — ThreatFox adapter (abuse.ch).

IOC sharing platform feeding malware-associated indicators with confidence
levels: https://threatfox.abuse.ch/api/

Since 2025 the ThreatFox API requires a free ``Auth-Key`` for data queries
(obtained via the abuse.ch authentication portal). The adapter never turns
a *missing* key into an error state: keyless POSTs still answer with a
``query_status`` payload, which proves the API is reachable, so the source
reports itself as ONLINE while keyless community feeds stay fully live.
"""

from __future__ import annotations

from ..utils.validators import TYPE_DOMAIN, TYPE_IP, TYPE_IP6, TYPE_URL, NormalizedIndicator
from .base import ProviderAdapter, ProviderNotConfigured, finding

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
KEY_URL = "https://auth.abuse.ch/"


class ThreatFoxProvider(ProviderAdapter):
    name = "threatfox"
    display_name = "ThreatFox"
    requires_key = True
    description = (
        "abuse.ch IOC database: indicators extracted from malware with malware "
        "family, confidence level and first-seen metadata. Requires a free "
        "Auth-Key (abuse.ch authentication portal)."
    )
    capabilities = ("ioc-intelligence", "malware-families", "ip-reputation",
                    "domain-intelligence", "url-intelligence")
    docs_url = "https://threatfox.abuse.ch/api/"
    key_url = KEY_URL
    default_ttl = 2 * 3600
    min_interval = 2.0
    test_url = API_URL
    test_method = "POST"
    test_json = {"query": "get_iocs", "days": 1}

    def auth_headers(self) -> dict:
        key = self.api_key()
        return {"Auth-Key": key} if key else {}

    # ------------------------------------------------- keyless-safe testing
    def test_connection(self) -> str:
        """
        Connectivity probe that never hard-fails merely for a missing key.

        abuse.ch answers keyless POSTs with ``query_status:
        "missing_auth_key"`` — that response itself proves the API is up,
        so it is reported as reachable (online) instead of an error. With a
        stored Auth-Key the same probe doubles as a credentials check.
        """
        try:
            payload = self.post_json(
                API_URL, json_body={"query": "get_iocs", "days": 1},
                headers=self.auth_headers(),
            )
        except ProviderNotConfigured:
            if not self.api_key():
                # Server demanded auth earlier than expected — it is reachable.
                return (f"{self.display_name} API reachable — free Auth-Key "
                        f"({KEY_URL}) unlocks full IOC queries.")
            raise
        status = (payload or {}).get("query_status", "")
        if self.api_key():
            if status == "ok":
                return f"{self.display_name} connection OK — Auth-Key accepted."
            if status in ("missing_auth_key", "unauthorized"):
                raise ProviderNotConfigured(
                    f"{self.display_name} rejected the stored Auth-Key — save a "
                    f"fresh free key from {KEY_URL} via Configure.")
            return f"{self.display_name} reachable (server status: {status})."
        return (f"{self.display_name} API reachable — free Auth-Key "
                f"({KEY_URL}) unlocks full IOC queries; keyless community "
                "sources stay live meanwhile.")

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP, TYPE_IP6, TYPE_DOMAIN, TYPE_URL)

    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        auth_key = self.api_key() or None
        headers = {"Auth-Key": auth_key} if auth_key else {}
        resp = self.http(
            "POST", API_URL,
            json_body={"query": "search_ioc", "search_indicator": norm.value},
            headers=headers,
        )
        payload = self._decode(resp)
        status = payload.get("query_status")
        data = payload.get("data") or []
        if isinstance(data, dict):
            data = [data]
        if status == "missing_auth_key" or status == "unauthorized":
            raise ProviderNotConfigured(
                "ThreatFox rejected the Auth-Key (or none stored) — save a valid "
                f"free key from {KEY_URL} via Configure.")
        if status in ("no_result", "error", "illegal_data_type") or not data:
            return [
                finding(
                    source=self.display_name,
                    severity="info",
                    confidence=0.85,
                    score=5,
                    summary=f"ThreatFox: no IOCs on record for {norm.value}.",
                    tags=["clean-on-threatfox"],
                    data={"ioc_count": 0},
                )
            ]

        malware_families: list[str] = []
        max_conf = 0.0
        first_seen = None
        ioc_records = []
        for item in data:
            malware = (item.get("malware_printable") or item.get("malware") or "").strip()
            if malware and malware not in malware_families:
                malware_families.append(malware)
            try:
                conf = float(item.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                conf = 0.0
            max_conf = max(max_conf, conf)
            fs = item.get("first_seen") or ""
            if fs and (not first_seen or fs < first_seen):
                first_seen = fs
            ioc_records.append({
                "ioc": item.get("ioc", ""),
                "malware": malware,
                "confidence": conf,
                "first_seen": fs,
                "reporter": item.get("reporter", ""),
            })

        top = max((r["confidence"] for r in ioc_records), default=0.0)
        score = int(min(100, 55 + top * 40))
        summary = (
            f"ThreatFox: {len(ioc_records)} IOC record(s) — "
            f"malware association: {', '.join(malware_families[:4]) or 'unspecified'}."
        )
        return [
            finding(
                source=self.display_name,
                severity="critical" if top >= 0.9 else "high" if top >= 0.75 else "medium",
                confidence=0.85,
                score=score,
                summary=summary,
                tags=["malware-delivery"] + [m.split()[0].lower() for m in malware_families[:4]],
                observed_at=(first_seen or "").replace("T", " ").split(".")[0] or None,
                data={"ioc_count": len(ioc_records), "records": ioc_records[:8]},
            )
        ]
