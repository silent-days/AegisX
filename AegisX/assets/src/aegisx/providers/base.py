"""
AegisX — provider framework.

Every intelligence provider is an adapter that turns an external API into
normalized ``Finding`` dicts. The base class provides:

  * API-key requirements & configuration state
  * token-bucket rate limiting
  * SQLite-backed response caching with per-provider TTL
  * HTTP helpers with timeouts and retry/backoff
  * source-status reporting hooks
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

import requests

from ..database.repository import Repository, iso, parse_iso, utcnow
from ..security.keystore import KeyStore
from ..utils.validators import NormalizedIndicator

log = logging.getLogger("aegisx.providers")


class ProviderError(Exception):
    """Base provider failure."""


class ProviderNotConfigured(ProviderError):
    """Provider requires credentials which are absent."""


class ProviderRateLimited(ProviderError):
    """Provider reported a rate limit."""


class ProviderHTTPError(ProviderError):
    """Non-200 response after retries."""


class TokenBucket:
    """Simple minimum-interval limiter per provider."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = float(min_interval)
        self._last = 0.0

    def acquire(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()


def finding(**kwargs) -> dict:
    """Build a normalized finding dict with defaults."""
    f = {
        "source": kwargs.get("source", "unknown"),
        "severity": kwargs.get("severity", "info"),
        "confidence": kwargs.get("confidence", 0.5),
        "score": kwargs.get("score"),
        "summary": kwargs.get("summary", ""),
        "tags": kwargs.get("tags", []),
        "observed_at": kwargs.get("observed_at") or iso(),
        "data": kwargs.get("data", {}),
        "enrich": kwargs.get("enrich", {}),
    }
    return f


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


class ProviderAdapter(ABC):
    """Abstract base for all intelligence provider adapters."""

    name: str = "provider"
    display_name: str = "Provider"
    requires_key: bool = False
    description: str = ""
    capabilities: tuple[str, ...] = ()
    docs_url: str = ""
    key_url: str = ""            # where a (free) API key can be obtained
    default_ttl: int = 6 * 3600
    min_interval: float = 1.0            # seconds between live requests
    timeout: tuple[float, float] = (6.0, 20.0)
    retries: int = 1

    def __init__(self, keystore: KeyStore, repo: Repository) -> None:
        self.keystore = keystore
        self.repo = repo
        self._bucket = TokenBucket(self.min_interval)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "AegisX/1.0 (ThreatIntel; Kali Linux)"})

    # ------------------------------------------------------------- config
    def api_key(self) -> str:
        return self.keystore.get_key(self.name)

    def is_configured(self) -> bool:
        return (not self.requires_key) or bool(self.api_key())

    def configure_state(self) -> str:
        if not self.requires_key:
            return "ready"
        return "ready" if self.api_key() else "not-configured"

    def auth_headers(self) -> dict:
        """Extra headers carrying credentials (merged into every test call)."""
        return {}

    # ------------------------------------------------------------- cache
    def cache_key(self, norm: NormalizedIndicator) -> str:
        return f"{self.name}:{norm.type}:{norm.value.lower()}"

    def cached(self, norm: NormalizedIndicator) -> list[dict] | None:
        rec = self.repo.cache_get(self.cache_key(norm))
        return rec["payload"] if rec else None

    def store_cache(self, norm: NormalizedIndicator, findings: list[dict]) -> None:
        self.repo.cache_set(self.cache_key(norm), self.name, findings, self.default_ttl)

    # ---------------------------------------------------------------- http
    def http(self, method: str, url: str, *, params: dict | None = None,
             json_body: dict | None = None, data: dict | None = None,
             headers: dict | None = None) -> requests.Response:
        attempt = 0
        last_exc: Exception | None = None
        while attempt <= self.retries:
            self._bucket.acquire()
            try:
                resp = self.session.request(
                    method, url, params=params, json=json_body, data=data,
                    headers=headers, timeout=self.timeout,
                )
                if resp.status_code == 429:
                    raise ProviderRateLimited(f"{self.display_name} rate limit exceeded")
                if resp.status_code in (401, 403):
                    raise ProviderNotConfigured(
                        f"{self.display_name} rejected credentials (HTTP {resp.status_code})"
                    )
                resp.raise_for_status()
                return resp
            except (ProviderRateLimited, ProviderNotConfigured):
                raise
            except requests.RequestException as e:
                last_exc = e
                attempt += 1
                if attempt <= self.retries:
                    time.sleep(0.8 * attempt)
        raise ProviderHTTPError(f"{self.display_name} request failed: {last_exc}")

    def get_json(self, url: str, **kw) -> Any:
        resp = self.http("GET", url, **kw)
        return self._decode(resp)

    def post_json(self, url: str, **kw) -> Any:
        resp = self.http("POST", url, **kw)
        return self._decode(resp)

    @staticmethod
    def _decode(resp: requests.Response) -> Any:
        text = resp.text.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if "text/html" in resp.headers.get("Content-Type", ""):
                raise ProviderError("Provider returned HTML instead of JSON — API may have changed")
            raise ProviderError("Provider returned invalid JSON")

    # ------------------------------------------------------------- lookup
    def lookup(self, norm: NormalizedIndicator, *, force_refresh: bool = False) -> list[dict]:
        """Template method: config check -> cache -> live fetch -> parse -> cache."""
        if not self.is_configured():
            raise ProviderNotConfigured(
                f"{self.display_name} requires an API key (configure it in Settings → Intelligence Sources)"
            )
        if not force_refresh:
            cached = self.cached(norm)
            if cached is not None:
                return cached
        if not self.supports(norm):
            return []
        try:
            findings = self.fetch(norm)
        except ProviderError:
            raise
        except Exception as e:  # noqa: BLE001
            raise ProviderError(f"{self.display_name}: unexpected error — {e}") from e
        self.store_cache(norm, findings)
        return findings

    # ------------------------------------------------------- connectivity test
    test_url: str = ""
    test_method: str = "GET"
    test_params: dict = {}
    test_data: dict = {}
    test_json: dict = {}
    test_headers: dict = {}

    def test_connection(self) -> str:
        """Cheap, real connectivity check used by the Settings UI."""
        if self.requires_key and not self.api_key():
            where = self.key_url or self.docs_url
            raise ProviderNotConfigured(
                f"{self.display_name} requires an API key"
                + (f" — get a free one at {where}" if where else " — enter one first."))
        if self.name == "geoip":
            return self._test_geoip()
        try:
            merged_headers = {**self.test_headers, **self.auth_headers()}
            if self.test_method == "POST":
                self.http("POST", self.test_url, data=self.test_data or None,
                          json_body=self.test_json or None,
                          headers=merged_headers or None)
            else:
                self.http("GET", self.test_url, params=self.test_params or None,
                          headers=merged_headers or None)
        except ProviderRateLimited:
            return f"{self.display_name} reachable (rate limited — try again shortly)."
        except ProviderNotConfigured:
            raise
        except ProviderError as e:
            raise ProviderError(str(e)) from e
        return f"{self.display_name} connection OK — credentials accepted."

    def _test_geoip(self) -> str:
        raise ProviderNotConfigured("GeoIP test runs automatically after the database path is saved.")

    def supports(self, norm: NormalizedIndicator) -> bool:
        """Whether this provider can look up this indicator type."""
        return True

    @abstractmethod
    def fetch(self, norm: NormalizedIndicator) -> list[dict]:
        """Query the live API and return normalized findings."""
        raise NotImplementedError
