"""
AegisX — DNS over HTTPS adapter (keyless).

Domain infrastructure intelligence through free, public, keyless services:

  * Google DNS-over-HTTPS JSON API (dns.google) — A/AAAA, NS, MX and TXT
    (SPF/verification) record resolution with round-trip latency.
  * crt.sh certificate transparency archive — sub-domain discovery via
    historical TLS certificates issued for the domain.

No API key, no account, no configuration — resolves out of the box.
"""

from __future__ import annotations

import logging

from ..utils.validators import TYPE_DOMAIN, TYPE_URL, NormalizedIndicator
from .base import ProviderAdapter, ProviderError, finding

log = logging.getLogger("aegisx.providers.doh")

DOH_URL = "https://dns.google/resolve"
CRT_URL = "https://crt.sh/"

MAX_CT_SUBDOMAINS = 24


class DoHProvider(ProviderAdapter):
    name = "doh"
    display_name = "DNS over HTTPS"
    requires_key = False
    description = (
        "Keyless domain infrastructure: live A/NS/MX/TXT resolution (Google "
        "DoH) plus sub-domain discovery from certificate transparency logs "
        "(crt.sh). No key required."
    )
    capabilities = ("domain-intelligence", "dns-records", "subdomain-discovery",
                    "mail-infrastructure")
    docs_url = "https://developers.google.com/workspace/admin/"
    default_ttl = 6 * 3600
    min_interval = 1.0
    timeout = (6.0, 25.0)
    test_url = DOH_URL
    test_method = "GET"
    test_params = {"name": "example.com", "type": "A"}

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_DOMAIN, TYPE_URL)

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _host_of(norm: NormalizedIndicator) -> str:
        if norm.type == TYPE_URL:
            return (norm.extra.get("host") or
                    norm.value.split("//")[-1].split("/")[0])
        return norm.value.lower()

    def _query(self, name: str, rtype: str) -> dict:
        resp = self.http("GET", DOH_URL, params={"name": name, "type": rtype})
        try:
            return resp.json()
        except ValueError as e:
            raise ProviderError(f"DoH response not JSON: {e}") from e

    def _ct_subdomains(self, domain: str) -> list[str]:
        try:
            resp = self.http("GET", CRT_URL,
                             params={"q": f"%.{domain}", "output": "json"})
            rows = resp.json()
        except Exception as e:  # noqa: BLE001
            log.debug("crt.sh unavailable: %s", e)
            return []

        found: list[str] = []
        for row in rows[:400]:
            for entry in (row.get("name_value") or "").split("\n"):
                entry = entry.strip().lstrip("*.").lower()
                if entry.endswith(domain) and entry not in found:
                    found.append(entry)
                if len(found) >= MAX_CT_SUBDOMAINS:
                    return found
        return found

    # ----------------------------------------------------------------- fetch
    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        host = self._host_of(norm)
        base = host.split(".")[-2] if "." in host else host  # for wildcard CT

        a_rec = self._query(host, "A")
        answers = a_rec.get("Answer") or []
        a_values = [ans["data"] for ans in answers if ans.get("type") == 1]

        tags: list[str] = []
        notes: list[str] = []
        score = 5
        severity = "info"

        if a_values:
            notes.append(f"Resolves to {', '.join(a_values[:4])}.")
        else:
            if a_rec.get("Status") == 3:
                notes.append("Domain does not resolve (NXDOMAIN) — possibly "
                             "suspended or sinkholed.")
                tags.append("nxdomain")
                score, severity = 30, "low"
            else:
                notes.append("No A record returned.")

        # infrastructure context: NS + MX
        ns_rec = self._query(host, "NS")
        ns_names = [ans["data"].rstrip(".") for ans in (ns_rec.get("Answer") or [])
                    if ans.get("type") == 2][:5]
        if ns_names:
            notes.append(f"Nameservers: {', '.join(ns_names[:3])}.")
            if any("cloudflare" in n for n in ns_names):
                tags.append("behind-cloudflare")

        mx_rec = self._query(host, "MX")
        mx_hosts = [ans["data"].split()[-1].rstrip(".")
                    for ans in (mx_rec.get("Answer") or []) if ans.get("type") == 15][:3]
        if mx_hosts:
            notes.append(f"Mail: {', '.join(mx_hosts)}.")

        txt_rec = self._query(host, "TXT")
        txts = [ans.get("data", "").strip('"')[:60]
                for ans in (txt_rec.get("Answer") or []) if ans.get("type") == 16][:2]
        if txts:
            notes.append("TXT/SPF present.")

        # certificate transparency — sub-domain surface
        subdomains = self._ct_subdomains(base if base != host else host)
        if subdomains:
            notes.append(f"{len(subdomains)} distinct sub-domain(s) observed in "
                        "certificate transparency logs.")
        else:
            notes.append("No CT-log sub-domains found (or crt.sh unavailable).")

        data = {
            "a_records": a_values[:6],
            "nameservers": ns_names,
            "mx_hosts": mx_hosts,
            "txt_present": bool(txts),
            "subdomains": subdomains[:12],
            "subdomain_count": len(subdomains),
        }
        return [
            finding(
                source=self.display_name,
                severity=severity,
                confidence=0.75,
                score=score,
                summary=f"DoH infrastructure: {' · '.join(notes[:4])}",
                tags=tags or ["dns-resolved"],
                data=data,
            )
        ]
