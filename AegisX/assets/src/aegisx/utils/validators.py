"""
AegisX — indicator normalization & validation.

All intelligence that enters the platform passes through this module so the
rest of the system only ever deals with canonical indicator values.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

TYPE_IP = "ip"
TYPE_IP6 = "ipv6"
TYPE_DOMAIN = "domain"
TYPE_URL = "url"
TYPE_HASH = "hash"

ALL_TYPES = (TYPE_IP, TYPE_IP6, TYPE_DOMAIN, TYPE_URL, TYPE_HASH)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}\.?$"
)
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

# RFC 5737 / RFC 3849 documentation ranges — used by demonstration data.
_DOC_RANGES_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_DOC_RANGES_V6 = (ipaddress.ip_network("2001:db8::/32"),)


@dataclass
class NormalizedIndicator:
    """A canonicalized threat indicator."""

    raw: str
    type: str
    value: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"raw": self.raw, "type": self.type, "value": self.value, "extra": self.extra}


def normalize_ip(raw: str) -> NormalizedIndicator | None:
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    t = TYPE_IP if ip.version == 4 else TYPE_IP6
    extra = {"private": ip.is_private, "routable": ip.is_global}
    return NormalizedIndicator(raw=raw.strip(), type=t, value=str(ip), extra=extra)


def normalize_domain(raw: str) -> NormalizedIndicator | None:
    value = raw.strip().lower().rstrip(".")
    if len(value) < 4 or len(value) > 253 or " " in value:
        return None
    if _DOMAIN_RE.match(value):
        return NormalizedIndicator(raw=raw.strip(), type=TYPE_DOMAIN, value=value)
    return None


def normalize_url(raw: str) -> NormalizedIndicator | None:
    value = raw.strip()
    if not value.lower().startswith(("http://", "https://")):
        return None
    try:
        parsed = urlparse(value)
    except ValueError:
        return None
    if not parsed.netloc or "." not in parsed.netloc.split("@")[-1]:
        return None
    host = parsed.hostname or ""
    if not host:
        return None
    extra = {"host": host.lower(), "scheme": parsed.scheme, "path": parsed.path or "/"}
    return NormalizedIndicator(raw=value, type=TYPE_URL, value=value, extra=extra)


def normalize_hash(raw: str) -> NormalizedIndicator | None:
    value = raw.strip().lower()
    if not _HASH_RE.match(value):
        return None
    algo = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    return NormalizedIndicator(raw=raw.strip(), type=TYPE_HASH, value=value, extra={"algo": algo})


def normalize(raw: str) -> NormalizedIndicator | None:
    """Detect and normalize any supported indicator type."""
    if raw is None:
        return None
    raw = str(raw).strip().strip("'\"")
    if not raw:
        return None

    if raw.lower().startswith(("http://", "https://")):
        norm = normalize_url(raw)
        if norm:
            return norm
        # fall through: the host of a malformed URL may still be a domain
        return normalize_domain(raw.split("//", 1)[-1].split("/")[0])

    norm = normalize_hash(raw)
    if norm:
        return norm
    norm = normalize_ip(raw)
    if norm:
        return norm
    return normalize_domain(raw)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_documentation_ip(value: str) -> bool:
    """True for RFC 5737 TEST-NET addresses (used by demo data)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    nets = _DOC_RANGES_V4 if ip.version == 4 else _DOC_RANGES_V6
    return any(ip in n for n in nets)


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def sanitize_filename(name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip()
    return (name or "untitled")[:80]


def validate_investigation_name(name: str) -> tuple[bool, str]:
    name = (name or "").strip()
    if len(name) < 3:
        return False, "Investigation name must be at least 3 characters long."
    if len(name) > 80:
        return False, "Investigation name must be at most 80 characters long."
    return True, ""
