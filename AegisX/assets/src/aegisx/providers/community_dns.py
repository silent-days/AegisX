"""
AegisX — Community DNS Intel adapter (keyless).

Zero-configuration reputation intelligence through the Internet's own
DNS infrastructure — no API key, no account, no setup:

  * Spamhaus DBL (dbl.spamhaus.org) — domain blocklist (phishing, malware,
    botnet C2) queried via direct DNS resolution.
  * Spamhaus ZEN composite (zen.spamhaus.org) — IP reputation across
    SBL/XBL/PBL for IP indicators.
  * Tor exit-node membership (check.torproject.org bulk list) — flags
    anonymizing exit relays.
  * Reverse DNS (PTR) context for IP indicators.

Result codes follow the Spamhaus public-query convention (127.0.x.x);
127.255.255.x answers indicate query refusal (public resolver limits) and
are reported as inconclusive rather than malicious.
"""

from __future__ import annotations

import logging
import socket

from ..utils.validators import TYPE_DOMAIN, TYPE_IP, TYPE_IP6, TYPE_URL, NormalizedIndicator
from .base import ProviderAdapter, finding

log = logging.getLogger("aegisx.providers.community_dns")

TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
DBL_ZONE = "dbl.spamhaus.org"
ZEN_ZONE = "zen.spamhaus.org"

# 127.0.1.x — DBL (domain) return codes
DBL_CODES = {
    "127.0.1.2": "phishing domain",
    "127.0.1.4": "botnet C2 domain",
    "127.0.1.5": "spam domain",
    "127.0.1.6": "botnet C2 domain",
    "127.0.1.102": "abused legit domain",
    "127.0.1.255": "blocked (IP queries prohibited)",
}

# 127.0.0.x — ZEN (IP) return codes
ZEN_CODES = {
    "127.0.0.2": "Spamhaus SBL — spam source",
    "127.0.0.3": "Spamhaus SBL — spam operation",
    "127.0.0.4": "XBL — CBL compromised host / open proxy",
    "127.0.0.5": "XBL — NJABL open proxy",
    "127.0.0.6": "XBL — abused relay",
    "127.0.0.9": "SBL — hijacked netblock",
    "127.0.0.10": "PBL — residential IP (policy, not malicious)",
    "127.0.0.11": "PBL — residential IP (policy, not malicious)",
}


class CommunityDNSProvider(ProviderAdapter):
    name = "community_dns"
    display_name = "Community DNS Intel"
    requires_key = False
    description = (
        "Keyless reputation intelligence via DNS: Spamhaus DBL/ZEN blocklists, "
        "Tor exit-node detection and reverse DNS — works instantly with no key."
    )
    capabilities = ("ip-reputation", "domain-intelligence", "tor-detection",
                    "blacklist-check", "reverse-dns")
    docs_url = "https://www.spamhaus.org/dbl/"
    default_ttl = 12 * 3600
    min_interval = 1.5
    timeout = (3.0, 12.0)
    test_url = TOR_EXIT_URL
    test_method = "GET"

    def supports(self, norm: NormalizedIndicator) -> bool:
        return norm.type in (TYPE_IP, TYPE_IP6, TYPE_DOMAIN, TYPE_URL)

    # ------------------------------------------------------------ dns utils
    @staticmethod
    def _resolve(name: str) -> str | None:
        """Return the first A record for *name* or None (NXDOMAIN/refused)."""
        try:
            infos = socket.getaddrinfo(name, None, socket.AF_INET,
                                       socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr.startswith("127."):
                    return addr
            return infos[0][4][0] if infos else None
        except (socket.gaierror, OSError, IndexError):
            return None

    @staticmethod
    def _reverse_name(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    def _is_tor_exit(self, ip: str) -> bool | None:
        """True/False membership, None when the bulk list is unreachable."""
        try:
            resp = self.http("GET", TOR_EXIT_URL)
            exits = resp.text.split()
            return ip in exits
        except Exception as e:  # noqa: BLE001
            log.debug("Tor exit list unavailable: %s", e)
            return None

    # ------------------------------------------------------------------ ip
    def _ip_findings(self, norm: NormalizedIndicator) -> list[dict]:
        ip = norm.value
        parts = ip.split(".")
        reversed_ip = ".".join(reversed(parts))
        zen = self._resolve(f"{reversed_ip}.{ZEN_ZONE}")

        notes: list[str] = []
        tags: list[str] = []
        score = 5
        severity = "info"
        confidence = 0.8

        if zen is not None and zen.startswith("127.255."):
            notes.append("Spamhaus public query refused (public resolver limit) — "
                         "reputation inconclusive.")
        elif zen in ZEN_CODES:
            meaning = ZEN_CODES[zen]
            tags.append("spamhaus-listed")
            if zen.startswith("127.0.0.10") or zen.startswith("127.0.0.11"):
                severity, score = "low", 25
                tags.append("residential-policy")
            elif zen.startswith("127.0.0.4") or zen == "127.0.0.5":
                severity, score = "critical", 88
                tags += ["compromised-host", "open-proxy"]
            else:
                severity, score = "high", 72
                tags += ["spam-source"]
            notes.append(f"Listed on Spamhaus ZEN ({zen}) — {meaning}.")
        else:
            notes.append("Not listed on the Spamhaus ZEN composite blocklist.")

        tor = self._is_tor_exit(ip)
        if tor:
            tags.append("tor-exit-node")
            notes.append("IP is a live Tor exit relay — traffic is anonymized.")
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if rank["medium"] > rank[severity]:
                severity = "medium"
            score = max(score, 55)
        elif tor is False:
            notes.append("Not a Tor exit relay.")

        ptr = self._reverse_name(ip)
        if ptr:
            notes.append(f"Reverse DNS: {ptr}.")

        summary = f"Community DNS: {' · '.join(notes[:3])}"
        return [
            finding(
                source=self.display_name,
                severity=severity,
                confidence=confidence,
                score=score,
                summary=summary,
                tags=tags or ["clean-on-community-dns"],
                data={"zen_code": zen, "tor_exit": tor, "ptr": ptr},
            )
        ]

    # --------------------------------------------------------------- domain
    def _domain_findings(self, norm: NormalizedIndicator) -> list[dict]:
        domain = norm.value.lower()
        if domain.endswith(f".{DBL_ZONE}"):
            domain = domain[: -len(DBL_ZONE) - 1]
        # URL indicators: query the host part
        if norm.type == TYPE_URL:
            domain = (norm.extra.get("host") or domain).split("/")[0].split(":")[0]
        if not domain or "." not in domain:
            return []

        code = self._resolve(f"{domain}.{DBL_ZONE}")

        if code is not None and code.startswith("127.255."):
            summary = (f"Community DNS: Spamhaus DBL refused the public query "
                       f"(resolver limit) — {domain} reputation inconclusive.")
            return [finding(
                source=self.display_name, severity="info", confidence=0.6,
                score=10, summary=summary, tags=["dbl-inconclusive"],
                data={"dbl_code": code},
            )]
        if code in DBL_CODES:
            meaning = DBL_CODES[code]
            severity = ("critical" if code in ("127.0.1.2", "127.0.1.4", "127.0.1.6")
                       else "high")
            score = 85 if severity == "critical" else 68
            return [finding(
                source=self.display_name, severity=severity, confidence=0.9,
                score=score,
                summary=(f"Community DNS: {domain} is listed on the Spamhaus DBL "
                         f"— {meaning} ({code})."),
                tags=["spamhaus-dbl", "blacklisted"] +
                      (["phishing"] if code == "127.0.1.2" else
                       ["botnet-c2"] if code in ("127.0.1.4", "127.0.1.6") else []),
                data={"dbl_code": code, "dbl_meaning": meaning},
            )]
        return [finding(
            source=self.display_name, severity="info", confidence=0.8, score=5,
            summary=f"Community DNS: {domain} is not on the Spamhaus DBL blocklist.",
            tags=["clean-on-dbl"], data={"dbl_code": None},
        )]

    # ---------------------------------------------------------------- entry
    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        if norm.type in (TYPE_IP, TYPE_IP6):
            if norm.type == TYPE_IP6:
                return []  # ZEN IPv4 zones only; IPv6 skipped gracefully
            return self._ip_findings(norm)
        return self._domain_findings(norm)
