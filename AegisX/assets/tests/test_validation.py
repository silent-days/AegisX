"""AegisX validation tests: demo-data integrity, keystore, imports, integration."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class TestDemoDataIntegrity:
    """Demonstration data must only ever use documentation ranges."""

    def test_demo_ips_are_documentation_ranges(self):
        from aegisx.utils.demo_data import demo_ip
        import random

        rng = random.Random(1234)
        for _ in range(200):
            ip = ipaddress.ip_address(demo_ip(rng))
            assert ip.version == 4
            assert any(ip in net for net in DOC_NETS), ip

    def test_demo_domains_use_reserved_tlds(self):
        from aegisx.utils.demo_data import demo_domain
        import random

        rng = random.Random(99)
        allowed = (".example", ".test", ".invalid", ".localhost")
        for _ in range(100):
            d = demo_domain(rng)
            assert d.endswith(allowed), d

    def test_demo_locations_have_coordinates(self):
        from aegisx.utils.demo_data import demo_geo_for

        g = demo_geo_for("192.0.2.5")
        assert -90 <= g["lat"] <= 90 and -180 <= g["lon"] <= 180
        assert g["country"] and g["asn"]

    def test_demo_campaigns_are_labelled(self):
        from aegisx.utils.demo_data import DEMO_CAMPAIGNS

        for camp in DEMO_CAMPAIGNS:
            assert "SAMPLE" in camp["description"]
            assert camp["attribution"] == ""  # demo campaigns never attribute

    def test_demo_engine_is_deterministic(self):
        from aegisx.utils.demo_data import demo_geo_for

        assert demo_geo_for("192.0.2.5") == demo_geo_for("192.0.2.5")
        assert demo_geo_for("192.0.2.5") != demo_geo_for("198.51.100.5")


class TestKeyStore:
    def test_file_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGISX_CONFIG_HOME", str(tmp_path / "cfg"))
        from aegisx.security.keystore import KeyStore

        ks = KeyStore()
        ks.backend = "file"  # force deterministic path for the test
        ks.set_key("abuseipdb", "secret-key")
        assert ks.has_key("abuseipdb")
        assert ks.get_key("abuseipdb") == "secret-key"
        ks.set_key("abuseipdb", "")  # empty deletes
        assert ks.get_key("abuseipdb") == ""

    def test_key_file_permissions(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGISX_CONFIG_HOME", str(tmp_path / "cfg"))
        import os

        from aegisx.security.keystore import KeyStore

        ks = KeyStore()
        ks.backend = "file"
        ks.set_key("otx", "k" * 32)
        key_file = tmp_path / "cfg" / "keys.json"
        if key_file.is_file():
            mode = key_file.stat().st_mode & 0o777
            assert mode == 0o600, f"key file must be 0600, got {oct(mode)}"


class TestValidators:
    def test_documentation_ip_helper(self):
        from aegisx.utils.validators import is_documentation_ip

        assert is_documentation_ip("192.0.2.44") is True
        assert is_documentation_ip("8.8.8.8") is False
        assert is_documentation_ip("not-ip") is False

    def test_sanitize_filename(self):
        from aegisx.utils.validators import sanitize_filename

        assert sanitize_filename("a/b:c*d") == "a_b_c_d"
        assert sanitize_filename("") == "untitled"


class TestEngineIntegration:
    """Full pipeline on a temp database (demo mode)."""

    @pytest.fixture()
    def hub(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGISX_DB", str(tmp_path / "int.db"))
        monkeypatch.setenv("AEGISX_CONFIG_HOME", str(tmp_path / "cfg"))
        monkeypatch.setenv("AEGISX_STATE_HOME", str(tmp_path / "state"))
        from aegisx.core.services import ServiceHub

        ServiceHub._instance = None
        hub = ServiceHub.create()
        # These integration tests exercise the labelled demonstration path
        # (no network); production defaults to live keyless providers.
        hub.engine.demo_mode = True
        return hub

    def test_demo_lookup_produces_labelled_findings(self, hub):
        report = hub.engine.lookup("192.0.2.123")
        assert report is not None
        assert report["demo"] is True
        for f in report["findings"]:
            assert "(Demo)" in f["source"]
            assert "[SAMPLE DATA]" in f["summary"]
        assert 0 <= report["risk"]["score"] <= 100
        assert report["risk"]["factors"]

    def test_invalid_indicator_rejected(self, hub):
        assert hub.engine.lookup("!!not-an-indicator!!") is None

    def test_persistence_after_lookup(self, hub):
        hub.engine.lookup("203.0.113.50")
        ind = hub.repo.get_indicator_by_value("203.0.113.50")
        assert ind is not None and ind["demo"] == 1
        assert hub.repo.findings_for_indicator(ind["id"])

    def test_relationship_derivation(self, hub):
        # 30 demo indicators across 50 ASN buckets -> collision is certain
        for i in range(30):
            hub.engine.lookup(f"192.0.2.{i + 180}")
        assert hub.repo.relationship_count() >= 1

    def test_demo_mode_event_published(self, hub):
        hub.engine.lookup("192.0.2.77")
        kinds = [e.kind for e in hub.events.recent(20)]
        assert "lookup.completed" in kinds


class TestReports:
    def test_html_report_generation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGISX_DB", str(tmp_path / "r.db"))
        monkeypatch.setenv("AEGISX_STATE_HOME", str(tmp_path / "state"))
        from aegisx.core.services import ServiceHub
        from aegisx.reports import build_report, export_report

        ServiceHub._instance = None
        hub = ServiceHub.create()
        iid = hub.repo.upsert_indicator("192.0.2.31", "ip")
        hub.repo.add_finding(iid, source="URLhaus (Demo)", severity="high", score=80,
                             summary="[SAMPLE DATA] test finding")
        hub.repo.score_indicator(iid, 80, "high", 0.8)
        inv = hub.repo.create_investigation("Report Test Case")
        hub.repo.add_investigation_item(inv, iid)

        payload = build_report(hub.repo, investigation_id=inv)
        monkeypatch.setenv("AEGISX_DATA_HOME", str(tmp_path / "data"))
        from aegisx.utils.paths import reports_dir

        path = reports_dir() / "test-report.html"
        out = export_report(payload, "html", filename=str(path))
        html = Path(out).read_text(encoding="utf-8")
        assert "AegisX Intelligence Report" in html
        assert "192.0.2.31" in html
        assert "Methodology" in html
        assert "Silent Days" in html


class TestImports:
    def test_full_package_imports(self):
        import importlib

        for mod in (
            "aegisx",
            "aegisx.main",
            "aegisx.core",
            "aegisx.core.risk_engine",
            "aegisx.core.correlation_engine",
            "aegisx.core.intelligence_engine",
            "aegisx.core.mitre",
            "aegisx.providers",
            "aegisx.providers.base",
            "aegisx.database",
            "aegisx.security",
            "aegisx.utils",
            "aegisx.reports",
            "aegisx.version",
        ):
            importlib.import_module(mod)

    def test_version_constants(self):
        from aegisx.version import APP_AUTHOR, APP_NAME, APP_VERSION

        assert APP_NAME == "AegisX"
        assert APP_AUTHOR == "Silent Days"
        assert APP_VERSION == "1.0.0"
