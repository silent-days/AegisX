"""AegisX provider tests — offline: parsing, caching, rate limiting, config state."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aegisx.database.repository import Repository  # noqa: E402
from aegisx.providers import PROVIDER_CLASSES  # noqa: E402
from aegisx.providers.abuseipdb import AbuseIPDBProvider  # noqa: E402
from aegisx.providers.base import (  # noqa: E402
    ProviderNotConfigured,
    TokenBucket,
    finding,
    severity_from_score,
)
from aegisx.providers.threatfox import ThreatFoxProvider  # noqa: E402
from aegisx.providers.urlhaus import URLhausProvider  # noqa: E402
from aegisx.providers.community_dns import CommunityDNSProvider  # noqa: E402
from aegisx.providers.dns_over_https import DoHProvider  # noqa: E402
from aegisx.providers.opengeo import OpenGeoProvider  # noqa: E402
from aegisx.security.keystore import KeyStore  # noqa: E402
from aegisx.utils.validators import normalize  # noqa: E402


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AEGISX_STATE_HOME", str(tmp_path / "state"))
    return Repository(tmp_path / "t.db")


@pytest.fixture()
def keystore(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGISX_CONFIG_HOME", str(tmp_path / "cfg"))
    ks = KeyStore()
    ks.backend = "file"
    return ks


class TestSeverityMapping:
    def test_bands(self):
        assert severity_from_score(90) == "critical"
        assert severity_from_score(75) == "high"
        assert severity_from_score(50) == "medium"
        assert severity_from_score(30) == "low"
        assert severity_from_score(10) == "info"

    def test_finding_defaults(self):
        f = finding(source="X")
        assert f["severity"] == "info"
        assert f["observed_at"]
        assert isinstance(f["tags"], list) and isinstance(f["data"], dict)


class TestTokenBucket:
    def test_min_interval_enforced(self):
        bucket = TokenBucket(0.25)
        t0 = time.monotonic()
        bucket.acquire()
        bucket.acquire()
        assert time.monotonic() - t0 >= 0.2


class TestConfiguration:
    def test_key_required_provider_not_configured(self, repo, keystore):
        p = AbuseIPDBProvider(keystore, repo)
        assert p.requires_key is True
        assert p.is_configured() is False

    def test_keyed_provider_configures(self, repo, keystore):
        p = AbuseIPDBProvider(keystore, repo)
        keystore.set_key("abuseipdb", "test-key-123")
        assert p.is_configured() is True
        assert p.api_key() == "test-key-123"

    def test_free_provider_always_configured(self, repo, keystore):
        p = CommunityDNSProvider(keystore, repo)
        assert p.requires_key is False
        assert p.is_configured() is True

    def test_abusech_providers_need_free_key(self, repo, keystore, monkeypatch):
        """abuse.ch requires an Auth-Key for ThreatFox/URLhaus data since 2025.

        A *missing* key must never surface as an error state: the keyless
        probe still proves reachability, so test_connection() reports the
        source as reachable with a free-key hint instead of raising.
        """
        tf = ThreatFoxProvider(keystore, repo)
        assert tf.requires_key is True
        assert tf.is_configured() is False

        class MissingKeyResp:
            text = '{"query_status": "missing_auth_key", "data": []}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(tf, "http", lambda *a, **kw: MissingKeyResp())
        msg = tf.test_connection()  # keyless-safe: reachable, no exception
        assert "reachable" in msg.lower()
        assert "auth.abuse.ch" in tf.key_url
        assert "auth.abuse.ch" in msg

        uh = URLhausProvider(keystore, repo)
        assert uh.requires_key is True
        assert uh.is_configured() is False

    def test_abusech_keyless_probe_http_401_still_reachable(self, repo, keystore, monkeypatch):
        """Even an early 401 (no key stored) is reported as reachable."""
        tf = ThreatFoxProvider(keystore, repo)

        def fake_http(*a, **kw):
            raise ProviderNotConfigured("ThreatFox rejected credentials (HTTP 401)")

        monkeypatch.setattr(tf, "http", fake_http)
        msg = tf.test_connection()
        assert "reachable" in msg.lower()

    def test_lookup_raises_when_unconfigured(self, repo, keystore):
        p = AbuseIPDBProvider(keystore, repo)
        norm = normalize("192.0.2.9")
        with pytest.raises(ProviderNotConfigured):
            p.lookup(norm)


class TestCache:
    def test_cache_roundtrip(self, repo, keystore):
        p = URLhausProvider(keystore, repo)
        norm = normalize("malware.example")
        payload = [finding(source="URLhaus", summary="cached test")]
        p.store_cache(norm, payload)
        cached = p.cached(norm)
        assert cached and cached[0]["summary"] == "cached test"

    def test_expired_cache_miss(self, repo, keystore):
        p = URLhausProvider(keystore, repo)
        norm = normalize("expired.example")
        p.repo.cache_set(p.cache_key(norm), p.name, [{"x": 1}], ttl_seconds=-10)
        assert p.cached(norm) is None


class TestParsers:
    """Offline parse tests with canned payloads (no network)."""

    def test_abuseipdb_parse(self, repo, keystore, monkeypatch):
        p = AbuseIPDBProvider(keystore, repo)

        class FakeResp:
            text = '{"data": {"abuseConfidenceScore": 88, "totalReports": 42, ' \
                   '"countryCode": "DE", "isp": "TestNet GmbH", "asn": 64512, ' \
                   '"usageType": "Data Center", "lastReportedAt": "2026-11-01T00:00:00+00:00"}}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("192.0.2.10"))
        assert findings[0]["score"] == 88
        assert findings[0]["severity"] == "critical"
        assert findings[0]["enrich"]["asn"] == "AS64512"
        assert "TestNet GmbH" in findings[0]["summary"]

    def test_urlhaus_clean_parse(self, repo, keystore, monkeypatch):
        p = URLhausProvider(keystore, repo)

        class FakeResp:
            text = '{"urls": []}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("clean.example"))
        assert findings[0]["severity"] == "info"
        assert findings[0]["score"] == 5

    def test_urlhaus_listed_parse(self, repo, keystore, monkeypatch):
        p = URLhausProvider(keystore, repo)

        class FakeResp:
            text = '{"urls": [{"url": "http://x.example/payload", "tags": ["mirai"], ' \
                   '"date_added": "2026-11-01", "payloads": [], "url_status": "online"}, ' \
                   '{"url": "http://x.example/gate.php", "tags": [], "date_added": ' \
                   '"2026-11-02", "payloads": [{"signature": "Mirai"}], "url_status": "offline"}]}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("bad.example"))
        assert findings[0]["score"] >= 60
        assert "mirai" in findings[0]["tags"]
        assert len(findings[0]["data"]["sample_urls"]) == 2

    def test_threatfox_ioc_parse(self, repo, keystore, monkeypatch):
        p = ThreatFoxProvider(keystore, repo)

        class FakeResp:
            text = '{"query_status": "ok", "data": [{"ioc": "192.0.2.55:4444", ' \
                   '"malware_printable": "AsyncRAT", "confidence": 90, ' \
                   '"first_seen": "2026-11-01T00:00:00.000000", "reporter": "abuse.ch"}]}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("192.0.2.55"))
        assert findings[0]["score"] >= 85
        assert any("asyncrat" in t for t in findings[0]["tags"])

    def test_threatfox_no_result(self, repo, keystore, monkeypatch):
        p = ThreatFoxProvider(keystore, repo)

        class FakeResp:
            text = '{"query_status": "no_result", "data": null}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("192.0.2.77"))
        assert findings[0]["score"] == 5

    def test_virustotal_parse(self, repo, keystore, monkeypatch):
        from aegisx.providers.virustotal import VirusTotalProvider

        p = VirusTotalProvider(keystore, repo)

        class FakeResp:
            text = '{"data": {"attributes": {"last_analysis_stats": {"malicious": 12, ' \
                   '"suspicious": 2, "harmless": 55, "undetected": 3}, ' \
                   '"last_analysis_results": {"EngineA": {"category": "malicious", ' \
                   '"result": "trojan.bot"}, "EngineB": {"category": "harmless", ' \
                   '"result": null}}, "reputation": -100}}}'

            def raise_for_status(self):
                return None

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("192.0.2.66"))
        assert findings[0]["score"] > 30
        assert "EngineA: trojan.bot" in findings[0]["data"]["detections"][0]

    def test_community_dns_dbl_listed(self, repo, keystore, monkeypatch):
        p = CommunityDNSProvider(keystore, repo)
        monkeypatch.setattr(p, "_resolve", lambda name: "127.0.1.2"
                            if name.endswith(".dbl.spamhaus.org") else None)
        findings = p.fetch(normalize("dbltest.com"))
        assert findings[0]["severity"] == "critical"
        assert findings[0]["score"] == 85
        assert "phishing" in findings[0]["summary"].lower()

    def test_community_dns_dbl_clean(self, repo, keystore, monkeypatch):
        p = CommunityDNSProvider(keystore, repo)
        monkeypatch.setattr(p, "_resolve", lambda _name: None)
        findings = p.fetch(normalize("clean.example"))
        assert findings[0]["severity"] == "info"
        assert findings[0]["score"] == 5

    def test_community_dns_zen_ip(self, repo, keystore, monkeypatch):
        p = CommunityDNSProvider(keystore, repo)
        monkeypatch.setattr(p, "_resolve",
                            lambda name: "127.0.0.2"
                            if name.endswith(".zen.spamhaus.org") else None)
        monkeypatch.setattr(p, "_is_tor_exit", lambda _ip: False)
        findings = p.fetch(normalize("127.0.0.2"))
        assert findings[0]["severity"] == "high"
        assert findings[0]["data"]["zen_code"] == "127.0.0.2"

    def test_opengeo_parse(self, repo, keystore, monkeypatch):
        p = OpenGeoProvider(keystore, repo)

        class FakeResp:
            def json(self):
                return {"success": True, "ip": "8.8.8.8", "city": "Mountain View",
                        "country": "United States", "country_code": "US",
                        "latitude": 37.4, "longitude": -122.0,
                        "connection": {"asn": 15169, "org": "Google LLC",
                                        "isp": "Google LLC"}}

        monkeypatch.setattr(p, "http", lambda *a, **kw: FakeResp())
        findings = p.fetch(normalize("8.8.8.8"))
        assert findings[0]["enrich"]["country"] == "US"
        assert findings[0]["enrich"]["asn"] == 15169
        assert "Google LLC" in findings[0]["summary"]

    def test_doh_parse(self, repo, keystore, monkeypatch):
        p = DoHProvider(keystore, repo)

        def fake_query(name, rtype):
            if rtype == "A":
                return {"Status": 0, "Answer": [
                    {"name": name, "type": 1, "data": "93.184.216.34"}]}
            if rtype == "NS":
                return {"Status": 0, "Answer": [
                    {"name": name, "type": 2, "data": "ns1.example.com."}]}
            return {"Status": 0, "Answer": []}

        monkeypatch.setattr(p, "_query", fake_query)
        monkeypatch.setattr(p, "_ct_subdomains",
                            lambda _d: ["a.example.com", "b.example.com"])
        findings = p.fetch(normalize("example.com"))
        assert findings[0]["data"]["a_records"] == ["93.184.216.34"]
        assert findings[0]["data"]["subdomain_count"] == 2


class TestSupports:
    def test_type_support_matrix(self, repo, keystore):
        urlhaus = URLhausProvider(keystore, repo)
        assert urlhaus.supports(normalize("http://x.example/1")) is True
        assert urlhaus.supports(normalize("192.0.2.1")) is False
        abuse = AbuseIPDBProvider(keystore, repo)
        assert abuse.supports(normalize("192.0.2.1")) is True
        assert abuse.supports(normalize("x.example")) is False


class TestRegistry:
    def test_all_nine_registered(self):
        assert set(PROVIDER_CLASSES) == {
            "community_dns", "doh", "opengeo", "geoip",
            "abuseipdb", "otx", "virustotal", "urlhaus", "threatfox",
        }

    def test_keyless_trio_needs_no_key(self, repo, keystore):
        for cls in (CommunityDNSProvider, DoHProvider, OpenGeoProvider):
            p = cls(keystore, repo)
            assert p.requires_key is False
            assert p.is_configured() is True
