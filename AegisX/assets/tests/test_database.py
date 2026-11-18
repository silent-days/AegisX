"""AegisX database repository tests (SQLite CRUD + cache + settings)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aegisx.database.repository import Repository  # noqa: E402


@pytest.fixture()
def repo(tmp_path):
    return Repository(tmp_path / "repo.db")


class TestIndicators:
    def test_upsert_idempotent(self, repo):
        a = repo.upsert_indicator("192.0.2.5", "ip", country="US")
        b = repo.upsert_indicator("192.0.2.5", "ip", country="DE")
        assert a == b
        assert repo.count_indicators() == 1

    def test_search_filters(self, repo):
        repo.upsert_indicator("192.0.2.5", "ip", country="US")
        repo.upsert_indicator("malware.example", "domain")
        repo.score_indicator(
            repo.get_indicator_by_value("192.0.2.5")["id"], 88, "critical", 0.9)
        ips = repo.search_indicators(type_="ip")
        assert len(ips) == 1 and ips[0]["severity"] == "critical"
        found = repo.search_indicators(query="malware")
        assert len(found) == 1 and found[0]["type"] == "domain"

    def test_tags_and_scoring(self, repo):
        iid = repo.upsert_indicator("192.0.2.8", "ip")
        repo.add_tag(iid, "c2")
        repo.add_tag(iid, "botnet")
        ind = repo.get_indicator(iid)
        assert set(ind["tags"]) == {"botnet", "c2"}
        repo.remove_tag(iid, "c2")
        assert repo.get_indicator(iid)["tags"] == ["botnet"]

    def test_delete_cascades(self, repo):
        iid = repo.upsert_indicator("192.0.2.9", "ip")
        repo.add_finding(iid, source="X", severity="high")
        repo.delete_indicator(iid)
        assert repo.findings_for_indicator(iid) == []


class TestFindings:
    def test_add_and_list(self, repo):
        iid = repo.upsert_indicator("198.51.100.3", "ip")
        repo.add_finding(iid, source="URLhaus", severity="high", score=85,
                         summary="listed", data={"url_count": 3})
        fs = repo.findings_for_indicator(iid)
        assert len(fs) == 1
        assert fs[0]["source"] == "URLhaus" and fs[0]["score"] == 85

    def test_sources_for_indicator(self, repo):
        iid = repo.upsert_indicator("198.51.100.4", "ip")
        repo.add_finding(iid, source="A")
        repo.add_finding(iid, source="B")
        assert sorted(repo.sources_for_indicator(iid)) == ["A", "B"]


class TestRelationships:
    def test_unique_constraint(self, repo):
        a = repo.upsert_indicator("192.0.2.1", "ip")
        b = repo.upsert_indicator("192.0.2.2", "ip")
        assert repo.add_relationship(a, b, "same-asn", "evidence", 0.7) is True
        assert repo.add_relationship(a, b, "same-asn", "dup", 0.7) is False
        assert repo.relationship_count() == 1

    def test_self_relationship_rejected(self, repo):
        a = repo.upsert_indicator("192.0.2.3", "ip")
        assert repo.add_relationship(a, a, "same-asn") is False


class TestCampaigns:
    def test_upsert_and_link(self, repo):
        cid = repo.upsert_campaign("Operation Test", tags=["x"], mitre=["T1566"])
        cid2 = repo.upsert_campaign("Operation Test", tags=["y"])
        assert cid == cid2
        iid = repo.upsert_indicator("192.0.2.10", "ip")
        repo.link_campaign_indicator(cid, iid)
        repo.link_campaign_indicator(cid, iid)  # duplicate link ignored
        camp = repo.get_campaign(cid)
        assert camp["indicator_count"] == 1
        assert camp["mitre"] == ["T1566"]


class TestInvestigations:
    def test_full_flow(self, repo):
        iid = repo.upsert_indicator("192.0.2.11", "ip")
        inv = repo.create_investigation("Case Alpha", priority="high")
        assert repo.add_investigation_item(inv, iid) is True
        assert repo.add_investigation_item(inv, iid) is False  # duplicate
        repo.add_note(inv, "analyst", "started triage")
        repo.update_investigation(inv, status="active")
        data = repo.get_investigation(inv)
        assert data["status"] == "active"
        assert len(data["notes"]) == 1
        items = repo.investigation_items(inv)
        assert len(items) == 1 and items[0]["value"] == "192.0.2.11"
        assert repo.open_investigation_count() == 1

    def test_remove_item(self, repo):
        iid = repo.upsert_indicator("192.0.2.12", "ip")
        inv = repo.create_investigation("Case Beta")
        repo.add_investigation_item(inv, iid)
        repo.remove_investigation_item(inv, iid)
        assert repo.investigation_items(inv) == []


class TestCache:
    def test_set_get_clear(self, repo):
        repo.cache_set("k", "provider", {"v": 1}, 3600)
        assert repo.cache_get("k")["payload"] == {"v": 1}
        repo.cache_set("k2", "provider", {"v": 2}, -1)  # already expired
        assert repo.cache_get("k2") is None
        assert repo.cache_clear() >= 1
        assert repo.cache_get("k") is None

    def test_stats(self, repo):
        repo.cache_set("a", "p", {"x": "y" * 100}, 60)
        s = repo.cache_stats()
        assert s["entries"] == 1 and s["bytes"] > 50


class TestSettingsAndEvents:
    def test_settings_roundtrip(self, repo):
        repo.set_setting("demo_mode", "1")
        assert repo.get_setting("demo_mode", "0") == "1"
        assert repo.get_setting("missing", "fallback") == "fallback"

    def test_events(self, repo):
        repo.add_event("lookup", "did something", severity="high", data={"a": 1})
        evs = repo.recent_events(5)
        assert evs[0]["message"] == "did something"
        assert evs[0]["data"]["a"] == 1


class TestSourceStatus:
    def test_state_transitions(self, repo):
        repo.set_source_state("abuseipdb", "online")
        repo.set_source_state("abuseipdb", "error", error="boom")
        states = {s["name"]: s for s in repo.source_states()}
        assert states["abuseipdb"]["state"] == "error"
        assert states["abuseipdb"]["failures"] == 1
        repo.set_source_state("abuseipdb", "online")
        states = {s["name"]: s for s in repo.source_states()}
        assert states["abuseipdb"]["last_success"]


class TestStatsQueries:
    def test_distributions_and_timeline(self, repo):
        for i in range(1, 6):
            iid = repo.upsert_indicator(f"192.0.2.{i}", "ip", country="US")
            repo.score_indicator(iid, 90, "critical", 0.8)
        for i in range(6, 9):
            iid = repo.upsert_indicator(f"malware{i}.example", "domain", country="DE")
            repo.score_indicator(iid, 30, "low", 0.5)
        stats = repo.stats()
        assert stats["total"] == 8 and stats["high_risk"] == 5
        assert stats["ips"] == 5 and stats["domains"] == 3
        assert repo.severity_distribution()["critical"] == 5
        assert repo.type_distribution()["ip"] == 5
        assert repo.top_field("country")[0]["key"] == "US"
        assert len(repo.activity_timeline(30)) >= 1
        assert len(repo.confidence_histogram()) == 5

    def test_wipe(self, repo):
        repo.upsert_indicator("192.0.2.99", "ip")
        repo.wipe_all()
        assert repo.count_indicators() == 0
