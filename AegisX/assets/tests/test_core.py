"""AegisX core engine tests: normalization, risk scoring, correlation, MITRE."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aegisx.core.correlation_engine import jaccard  # noqa: E402
from aegisx.core.mitre import ATTACK_TECHNIQUES, describe, techniques_for_tags  # noqa: E402
from aegisx.core.risk_engine import band_for, score_indicator  # noqa: E402
from aegisx.database.models import init_db  # noqa: E402
from aegisx.database.repository import Repository  # noqa: E402
from aegisx.utils.validators import (  # noqa: E402
    normalize,
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_url,
)


# ---------------------------------------------------------------- normalize
class TestNormalization:
    def test_ipv4(self):
        n = normalize_ip("203.0.113.5")
        assert n and n.type == "ip" and n.value == "203.0.113.5"

    def test_ipv4_invalid(self):
        assert normalize_ip("999.999.1.1") is None
        assert normalize_ip("not-an-ip") is None

    def test_ipv6(self):
        n = normalize_ip("2001:db8::1")
        assert n and n.type == "ipv6"

    def test_domain(self):
        n = normalize_domain("Malware.Example.")
        assert n and n.value == "malware.example"

    def test_domain_invalid(self):
        assert normalize_domain("no spaces here") is None
        assert normalize_domain("") is None

    def test_url(self):
        n = normalize_url("http://192.0.2.1:8080/payload/bin.sh")
        assert n and n.type == "url"
        assert n.extra["host"] == "192.0.2.1"

    def test_hash_detection(self):
        assert normalize_hash("d" * 64) is not None
        assert normalize_hash("a" * 40) is not None
        assert normalize_hash("b" * 32) is not None
        assert normalize_hash("c" * 31) is None

    def test_auto_detect(self):
        assert normalize("198.51.100.7").type == "ip"
        assert normalize("phishing.example").type == "domain"
        assert normalize("http://malware.example/x.bin").type == "url"
        assert normalize("e" * 64).type == "hash"
        assert normalize("") is None
        assert normalize(None) is None


# ---------------------------------------------------------------- risk
class TestRiskEngine:
    @staticmethod
    def _f(source, score, severity="high", tags=(), observed_at=None):
        return {"source": source, "score": score, "severity": severity,
                "tags": list(tags), "observed_at": observed_at}

    def test_bands(self):
        assert band_for(90) == "critical"
        assert band_for(72) == "high"
        assert band_for(50) == "medium"
        assert band_for(25) == "low"
        assert band_for(5) == "info"

    def test_single_source(self):
        r = score_indicator([self._f("URLhaus", 90, "high",
                                     observed_at="2026-11-17T00:00:00Z")])
        assert 80 <= r.score <= 100
        assert r.severity in ("high", "critical")
        assert r.factors, "factors must be present"

    def test_multi_source_corroboration_boosts(self):
        single = score_indicator([self._f("URLhaus", 70)])
        multi = score_indicator([
            self._f("URLhaus", 70), self._f("AbuseIPDB", 70), self._f("ThreatFox", 70),
        ])
        assert multi.score > single.score
        assert multi.confidence > single.confidence

    def test_critical_tags_escalate(self):
        base = score_indicator([self._f("AbuseIPDB", 60)])
        tagged = score_indicator([self._f("AbuseIPDB", 60, tags=("c2", "botnet"))])
        assert tagged.score > base.score

    def test_stale_evidence_decays(self):
        fresh = score_indicator([self._f("AbuseIPDB", 80, observed_at="2026-11-17T00:00:00Z")])
        old = score_indicator([self._f("AbuseIPDB", 80, observed_at="2024-01-01T00:00:00Z")])
        assert old.score < fresh.score

    def test_clean_indicator_scores_low(self):
        r = score_indicator([self._f("AbuseIPDB", 5, "info")])
        assert r.score <= 15
        assert r.verdict

    def test_no_scored_sources(self):
        r = score_indicator([{"source": "GeoIP", "severity": "info", "tags": []}])
        assert r.score <= 20


# ---------------------------------------------------------------- correlation
class TestCorrelation:
    def test_jaccard(self):
        assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
        assert jaccard({"a"}, set()) == 0.0
        assert 0 < jaccard({"a", "b"}, {"b", "c"}) < 1

    def test_same_asn_relationship(self, tmp_path):
        repo = Repository(tmp_path / "t.db")
        a = repo.upsert_indicator("192.0.2.1", "ip", asn="AS64512")
        b = repo.upsert_indicator("192.0.2.2", "ip", asn="AS64512")
        from aegisx.core.correlation_engine import CorrelationEngine

        eng = CorrelationEngine(repo)
        added = eng.derive_for_indicator(a)
        assert added >= 1
        rels = repo.relationships_for(a)
        assert any(r["kind"] == "same-asn" and r["target_id"] == b for r in rels)

    def test_cluster_union_find(self, tmp_path):
        repo = Repository(tmp_path / "t.db")
        ids = [repo.upsert_indicator(f"192.0.2.{i}", "ip") for i in range(1, 5)]
        for i in range(len(ids) - 1):
            repo.add_relationship(ids[i], ids[i + 1], "same-asn", "test", 0.7)
        from aegisx.core.correlation_engine import CorrelationEngine

        clusters = CorrelationEngine(repo).clusters()
        assert clusters and clusters[0]["size"] == 4


# ---------------------------------------------------------------- mitre
class TestMitre:
    def test_tag_mapping(self):
        techs = techniques_for_tags(["c2", "phishing"])
        assert "T1071" in techs and "T1566" in techs

    def test_technique_ids_known(self):
        for tags in (["dga"], ["ransomware"], ["bruteforce"], ["proxy"], ["spam"]):
            for tid in techniques_for_tags(tags):
                assert tid in ATTACK_TECHNIQUES

    def test_describe(self):
        name, tactic = describe("T1566")
        assert name == "Phishing" and tactic == "Initial Access"


# ---------------------------------------------------------------- models
def test_schema_migrations_apply(tmp_path):
    import sqlite3

    conn = sqlite3.connect(tmp_path / "x.db")
    init_db(conn)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version >= 1
