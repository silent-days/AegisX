"""
AegisX — URLhaus adapter (abuse.ch).

Malicious URL / malware distribution infrastructure tracker:
https://urlhaus.abuse.ch/api/

Since 2025 URLhaus API data queries require a free ``Auth-Key`` (abuse.ch
authentication portal). A missing key is never surfaced as an error: the
keyless probe still proves reachability, so the source reports itself as
reachable while keyless community feeds stay fully live.
"""

from __future__ import annotations

from ..utils.validators import TYPE_DOMAIN, TYPE_URL, NormalizedIndicator
from .base import ProviderAdapter, ProviderNotConfigured, finding

API_URL = "https://urlhaus-api.abuse.ch/v1/host/"
KEY_URL = "https://auth.abuse.ch/"


class URLhausProvider(ProviderAdapter):
    name = "urlhaus"
    display_name = "URLhaus"
    requires_key = True
    description = (
        "abuse.ch project tracking malware distribution URLs. Provides payload "
        "types (botnets, ransomware families), tags and URL lists per host. "
        "Requires a free Auth-Key (abuse.ch authentication portal)."
    )
    capabilities = ("malicious-urls", "malware-delivery", "domain-intelligence",
                    "payload-tracking")
    docs_url = "https://urlhaus.abuse.ch/api/"
    key_url = KEY_URL
    default_ttl = 2 * 3600
    min_interval = 2.0
    test_url = API_URL
    test_method = "POST"
    test_data = {"host": "example.com"}

    def auth_headers(self) -> dict:
        key = self.api_key()
        return {"Auth-Key": key} if key else {}

    # ------------------------------------------------- keyless-safe testing
    def test_connection(self) -> str:
        """
        Connectivity probe that never hard-fails merely for a missing key.

        abuse.ch answers keyless POSTs with a ``query_status`` payload —
        that response proves the API is up, so the source reports itself as
        reachable (online) instead of an error. With a stored Auth-Key the
        same probe doubles as a credentials check.
        """
        try:
            payload = self.post_json(API_URL, data={"host": "example.com"},
                                     headers=self.auth_headers())
        except ProviderNotConfigured:
            if not self.api_key():
                # Server demanded auth earlier than expected — it is reachable.
                return (f"{self.display_name} API reachable — free Auth-Key "
                        f"({KEY_URL}) unlocks malware-URL queries.")
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
                f"({KEY_URL}) unlocks malware-URL queries; keyless community "
                "sources stay live meanwhile.")

    def supports(self, norm: NormalizedIndicator) -> bool:
        if norm.type == TYPE_URL:
            return True
        if norm.type == TYPE_DOMAIN:
            return True
        return False

    def _host(self, norm: NormalizedIndicator) -> str:
        if norm.type == TYPE_URL:
            return norm.extra.get("host") or norm.value.split("//")[-1].split("/")[0]
        return norm.value

    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        host = self._host(norm)
        headers = self.auth_headers()
        resp = self.http("POST", API_URL, data={"host": host}, headers=headers)
        payload = self._decode(resp)

        urls = payload.get("urls") or []
        if not urls:
            return [
                finding(
                    source=self.display_name,
                    severity="info",
                    confidence=0.85,
                    score=5,
                    summary=f"URLhaus: no malware distribution URLs recorded for {host}.",
                    tags=["clean-on-urlhaus"],
                    data={"url_count": 0, "demo": False},
                )
            ]

        # Aggregate payload info
        tags: list[str] = []
        signatures: list[str] = []
        for u in urls:
            tags += [t for t in (u.get("tags") or []) if t]
            sig = u.get("signature") or (u.get("payloads") or [{}])[0].get("signature")
            if sig:
                signatures.append(sig)
        tags = sorted(set(tags))[:12]
        signatures = sorted(set(signatures))[:8]

        first_seen = urls[0].get("date_added") or None
        score = min(95, 60 + 5 * len(urls))
        summary = (
            f"URLhaus: {len(urls)} malware distribution URL(s) listed for {host}"
            + (f" — signatures: {', '.join(signatures[:4])}" if signatures else "")
            + "."
        )
        return [
            finding(
                source=self.display_name,
                severity="critical" if len(urls) >= 10 else "high" if len(urls) >= 3 else "medium",
                confidence=0.90,
                score=score,
                summary=summary,
                tags=tags + ["malware-delivery"],
                observed_at=first_seen,
                data={
                    "url_count": len(urls),
                    "signatures": signatures,
                    "sample_urls": [
                        {"url": u.get("url", ""), "status": u.get("url_status", "")}
                        for u in urls[:8]
                    ],
                    "blacklist_status": payload.get("blacklists", {}) or {},
                },
            )
        ]
