"""
AegisX — demonstration data engine.

ALL data produced by this module is clearly-labelled SAMPLE intelligence.
It uses only RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), RFC 3849 documentation IPv6 and reserved example domains,
so it can never be confused with real, live threat infrastructure.

Deterministic seeding (hash of the indicator value) makes demo results
stable between runs — an essential property for reproducible sessions.
"""

from __future__ import annotations

import hashlib
import random

# --------------------------------------------------------------------------
# Geography (seeded per indicator)
# --------------------------------------------------------------------------

_DEMO_LOCATIONS = [
    ("Karachi", "PK", 24.86, 67.01, "AS17557", "PTCL"),
    ("Lahore", "PK", 31.55, 74.34, "AS45696", "Multinet"),
    ("Moscow", "RU", 55.76, 37.62, "AS8359", "MTS"),
    ("Saint Petersburg", "RU", 59.93, 30.34, "AS12389", "Rostelecom"),
    ("Beijing", "CN", 39.90, 116.40, "AS4808", "China Unicom"),
    ("Shanghai", "CN", 31.23, 121.47, "AS4812", "China Telecom"),
    ("Tehran", "IR", 35.69, 51.39, "AS58224", "TCI"),
    ("Lagos", "NG", 6.52, 3.38, "AS37282", "MainOne"),
    ("São Paulo", "BR", -23.55, -46.63, "AS28573", "Claro"),
    ("New York", "US", 40.71, -74.01, "AS14061", "DigitalOcean"),
    ("Los Angeles", "US", 34.05, -118.24, "AS20473", "Vultr"),
    ("Chicago", "US", 41.88, -87.63, "AS7018", "AT&T"),
    ("London", "GB", 51.51, -0.13, "AS20473", "Choopa"),
    ("Paris", "FR", 48.86, 2.35, "AS16276", "OVH"),
    ("Frankfurt", "DE", 50.11, 8.68, "AS24940", "Hetzner"),
    ("Amsterdam", "NL", 52.37, 4.90, "AS60781", "LeaseWeb"),
    ("Kyiv", "UA", 50.45, 30.52, "AS15895", "Kyivstar"),
    ("Mumbai", "IN", 19.08, 72.88, "AS55836", "Reliance Jio"),
    ("Delhi", "IN", 28.61, 77.21, "AS9498", "Airtel"),
    ("Singapore", "SG", 1.35, 103.82, "AS16509", "Amazon"),
    ("Tokyo", "JP", 35.68, 139.69, "AS2516", "KDDI"),
    ("Seoul", "KR", 37.57, 126.98, "AS4766", "Korea Telecom"),
    ("Sydney", "AU", -33.87, 151.21, "AS1221", "Telstra"),
    ("Toronto", "CA", 43.65, -79.38, "AS577", "Bell"),
    ("Mexico City", "MX", 19.43, -99.13, "AS8151", "Uninet"),
    ("Istanbul", "TR", 41.01, 28.98, "AS9121", "Turk Telekom"),
    ("Dubai", "AE", 25.20, 55.27, "AS5384", "Etisalat"),
    ("Jakarta", "ID", -6.21, 106.85, "AS7713", "Telkom"),
    ("Manila", "PH", 14.60, 120.98, "AS9299", "PLDT"),
    ("Bangkok", "TH", 13.76, 100.50, "AS45758", "Triple T"),
    ("Hanoi", "VN", 21.03, 105.85, "AS7552", "Viettel"),
    ("Cairo", "EG", 30.04, 31.24, "AS8452", "TE Data"),
    ("Nairobi", "KE", -1.29, 36.82, "AS33771", "Safaricom"),
    ("Johannesburg", "ZA", -26.20, 28.04, "AS37457", "Telkom SA"),
    ("Buenos Aires", "AR", -34.60, -58.38, "AS7303", "Telecom Argentina"),
    ("Santiago", "CL", -33.45, -70.67, "AS7418", "Entel"),
    ("Bogotá", "CO", 4.71, -74.07, "AS10620", "Tigo"),
    ("Madrid", "ES", 40.42, -3.70, "AS12479", "Orange Spain"),
    ("Rome", "IT", 41.90, 12.50, "AS3269", "Telecom Italia"),
    ("Warsaw", "PL", 52.23, 21.01, "AS5617", "Orange PL"),
    ("Stockholm", "SE", 59.33, 18.07, "AS3301", "Telia"),
    ("Helsinki", "FI", 60.17, 24.94, "AS719", "Elisa"),
    ("Zurich", "CH", 47.38, 8.54, "AS3303", "Swisscom"),
    ("Dublin", "IE", 53.35, -6.26, "AS34218", "Vodafone IE"),
    ("Dhaka", "BD", 23.81, 90.41, "AS58715", "Link3"),
    ("Kuala Lumpur", "MY", 3.14, 101.69, "AS4788", "TM Net"),
    ("Hong Kong", "HK", 22.32, 114.17, "AS4760", "HKT"),
    ("Taipei", "TW", 25.03, 121.57, "AS3462", "HiNet"),
    ("Sofia", "BG", 42.70, 23.32, "AS8866", "Vivacom"),
    ("Bucharest", "RO", 44.43, 26.10, "AS8708", "RCS-RDS"),
    ("Vilnius", "LT", 54.69, 25.28, "AS8764", "TEO LT"),
    ("Oslo", "NO", 59.91, 10.75, "AS2119", "Telenor"),
]

_DEMO_SOURCE_POOL = ["AbuseIPDB", "VirusTotal", "AlienVault OTX", "URLhaus", "ThreatFox"]
DEMO_SOURCE_POOL = _DEMO_SOURCE_POOL  # public alias

DEMO_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


def demo_geo_for(value: str) -> dict:
    seed = int(hashlib.sha256(value.encode()).hexdigest()[:10], 16)
    city, cc, lat, lon, asn, asn_name = _DEMO_LOCATIONS[seed % len(_DEMO_LOCATIONS)]
    return {
        "city": city, "country": cc, "lat": lat, "lon": lon,
        "asn": asn, "asn_name": asn_name,
    }


def demo_ip(rng: random.Random) -> str:
    prefix = rng.choice(DEMO_IP_PREFIXES)
    return prefix + str(rng.randint(1, 254))


def demo_domain(rng: random.Random) -> str:
    words = ("secure", "update", "login", "vault", "cloud", "cdn", "api",
             "mail", "sync", "backup", "portal", "node", "pay", "verify")
    tld = rng.choice((".example", ".test", ".invalid", ".localhost"))
    parts = rng.sample(words, k=rng.randint(1, 3))
    return "-".join(parts) + tld


def demo_url(rng: random.Random) -> str:
    scheme = rng.choice(("http://", "http://"))     # demo payload URLs are plain HTTP
    host = demo_domain(rng)
    path = rng.choice(("/payload/", "/gate.php", "/panel/login", "/bin/arm7", "/update.bin"))
    return scheme + host + path


def demo_hash(rng: random.Random) -> str:
    return hashlib.sha256(str(rng.random()).encode()).hexdigest()


def sample_demo_indicators(count: int = 64) -> list[dict]:
    """A stable, labelled demo corpus for the whole platform."""
    rng = random.Random(0xAE51C)
    out: list[dict] = []
    makers = [demo_ip, demo_ip, demo_domain, demo_ip, demo_url, demo_domain, demo_hash]
    for i in range(count):
        maker = makers[i % len(makers)]
        value = maker(rng)
        geo = demo_geo_for(value)
        out.append({
            "value": value,
            "geo": geo,
        })
    return out


# --------------------------------------------------------------------------
# Demo campaigns (fictional names, labelled everywhere they are displayed)
# --------------------------------------------------------------------------

DEMO_CAMPAIGNS = [
    {
        "name": "Operation Rusted Shield",
        "description": "SAMPLE campaign: credential-phishing infrastructure rotating "
                       "through bulletproof hosting, linked by shared TLS certificate "
                       "issuers and convergent ASN usage.",
        "severity": "critical", "confidence": 0.72,
        "attribution": "", "attribution_confidence": 0.0,
        "tags": ["phishing", "bulletproof-hosting", "credential-phishing"],
        "mitre": ["T1566.002", "T1583", "T1071.001"],
        "days_back": 21,
    },
    {
        "name": "Emerald Botnet",
        "description": "SAMPLE campaign: Mirai-variant loader infrastructure with "
                       "fast-flux DNS and DGA-based command resolution.",
        "severity": "high", "confidence": 0.64,
        "attribution": "", "attribution_confidence": 0.0,
        "tags": ["botnet", "loader", "fast-flux", "dga"],
        "mitre": ["T1584", "T1071", "T1568"],
        "days_back": 34,
    },
    {
        "name": "Crimson Harvest",
        "description": "SAMPLE campaign: brute-force wave against exposed RDP and "
                       "VPN gateways, followed by session-cookie theft tooling.",
        "severity": "high", "confidence": 0.58,
        "attribution": "", "attribution_confidence": 0.0,
        "tags": ["bruteforce", "stealer", "scanner"],
        "mitre": ["T1110", "T1539", "T1595"],
        "days_back": 12,
    },
    {
        "name": "Silent Mirage",
        "description": "SAMPLE campaign: multi-hop proxy relay network masking "
                       "scan-then-exploit activity against public-facing services.",
        "severity": "medium", "confidence": 0.47,
        "attribution": "", "attribution_confidence": 0.0,
        "tags": ["proxy", "tor-exit", "exploit", "scanning"],
        "mitre": ["T1595", "T1190", "T1090.003"],
        "days_back": 47,
    },
    {
        "name": "Phantom Ledger",
        "description": "SAMPLE campaign: invoice-themed lure distribution through "
                       "compromised accounts and newly registered domains.",
        "severity": "medium", "confidence": 0.52,
        "attribution": "", "attribution_confidence": 0.0,
        "tags": ["phishing", "spam", "malware-delivery"],
        "mitre": ["T1566", "T1586.002", "T1204"],
        "days_back": 8,
    },
]

DEMO_INVESTIGATIONS = [
    {
        "name": "Edge Gateway Compromise Review",
        "description": "SAMPLE investigation: triage of anomalous outbound beacons "
                       "observed on the perimeter VPN appliance.",
        "status": "active", "priority": "high",
    },
    {
        "name": "Q3 Phishing Lure Triage",
        "description": "SAMPLE investigation: bulk review of reported lure URLs and "
                       "their hosting infrastructure.",
        "status": "open", "priority": "medium",
    },
    {
        "name": "Botnet Sinkhole Correlation",
        "description": "SAMPLE investigation: cross-referencing sinkhole hits with "
                       "known loader infrastructure.",
        "status": "closed", "priority": "low",
    },
]
