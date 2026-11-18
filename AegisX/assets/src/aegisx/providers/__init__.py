"""AegisX threat intelligence provider adapters."""

from .abuseipdb import AbuseIPDBProvider
from .base import (
    ProviderAdapter,
    ProviderError,
    ProviderHTTPError,
    ProviderNotConfigured,
    ProviderRateLimited,
    finding,
    severity_from_score,
)
from .community_dns import CommunityDNSProvider
from .dns_over_https import DoHProvider
from .geoip import GeoIPProvider
from .opengeo import OpenGeoProvider
from .otx import OTXProvider
from .threatfox import ThreatFoxProvider
from .urlhaus import URLhausProvider
from .virustotal import VirusTotalProvider

# Keyless community providers run with zero configuration; key-based
# adapters stay listed after them (Settings orders by importance).
PROVIDER_CLASSES: dict[str, type[ProviderAdapter]] = {
    "community_dns": CommunityDNSProvider,
    "doh": DoHProvider,
    "opengeo": OpenGeoProvider,
    "geoip": GeoIPProvider,
    "abuseipdb": AbuseIPDBProvider,
    "otx": OTXProvider,
    "virustotal": VirusTotalProvider,
    "urlhaus": URLhausProvider,
    "threatfox": ThreatFoxProvider,
}

__all__ = [
    "PROVIDER_CLASSES", "ProviderAdapter", "ProviderError", "ProviderHTTPError",
    "ProviderNotConfigured", "ProviderRateLimited", "finding", "severity_from_score",
    "AbuseIPDBProvider", "OTXProvider", "VirusTotalProvider", "URLhausProvider",
    "ThreatFoxProvider", "GeoIPProvider", "CommunityDNSProvider", "DoHProvider",
    "OpenGeoProvider",
]
