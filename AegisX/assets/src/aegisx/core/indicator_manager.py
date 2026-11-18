"""
AegisX — indicator lifecycle manager.

Normalization gate, persistence and lifecycle (active -> declining -> stale)
for all threat indicators entering the platform.
"""

from __future__ import annotations

from datetime import timedelta

from ..database.repository import Repository, iso, parse_iso, utcnow
from ..utils.validators import NormalizedIndicator, normalize

# Lifecycle thresholds (days since last_seen)
STALE_DAYS = 90
DECLINING_DAYS = 30


def lifecycle_status(last_seen: str | None) -> str:
    dt = parse_iso(last_seen)
    if not dt:
        return "stale"
    age = utcnow() - dt
    if age > timedelta(days=STALE_DAYS):
        return "stale"
    if age > timedelta(days=DECLINING_DAYS):
        return "declining"
    return "active"


class IndicatorManager:
    """Single entry point for indicator persistence."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    # ------------------------------------------------------------- normalize
    def normalize(self, raw: str) -> NormalizedIndicator | None:
        return normalize(raw)

    # ------------------------------------------------------------ upsert path
    def ensure_indicator(self, norm: NormalizedIndicator, *, demo: bool = False) -> int:
        """Create or refresh the base record; returns indicator id."""
        indicator_id = self.repo.upsert_indicator(norm.value, norm.type, demo=demo)
        self.repo.touch_indicator(indicator_id)
        return indicator_id

    def record_finding(self, indicator_id: int, finding: dict, *, demo: bool = False) -> None:
        """Persist a normalized provider finding."""
        self.repo.add_finding(
            indicator_id,
            source=finding.get("source", "unknown"),
            severity=finding.get("severity", "info"),
            confidence=finding.get("confidence", 0.0),
            score=finding.get("score"),
            summary=finding.get("summary", ""),
            data=finding.get("data", {}),
            observed_at=finding.get("observed_at"),
            demo=demo,
        )
        meta = finding.get("enrich") or {}
        self.repo.touch_indicator(
            indicator_id,
            country=meta.get("country"),
            asn=meta.get("asn"),
            asn_name=meta.get("asn_name"),
        )

    def finalize_scoring(self, indicator_id: int, result) -> None:
        self.repo.score_indicator(indicator_id, result.score, result.severity, result.confidence)

    # ------------------------------------------------------------- accessors
    def get(self, indicator_id: int) -> dict | None:
        ind = self.repo.get_indicator(indicator_id)
        if ind:
            ind["lifecycle"] = lifecycle_status(ind.get("last_seen"))
        return ind

    def get_by_value(self, value: str) -> dict | None:
        ind = self.repo.get_indicator_by_value(value)
        if ind:
            ind["lifecycle"] = lifecycle_status(ind.get("last_seen"))
        return ind

    def search(self, **kwargs) -> list[dict]:
        items = self.repo.search_indicators(**kwargs)
        for ind in items:
            ind["lifecycle"] = lifecycle_status(ind.get("last_seen"))
        return items

    def with_lifecycle(self, items: list[dict]) -> list[dict]:
        for ind in items:
            ind["lifecycle"] = lifecycle_status(ind.get("last_seen"))
        return items
