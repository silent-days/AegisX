"""AegisX — CSV import/export helpers for indicator exchange."""

from __future__ import annotations

import csv
from pathlib import Path

from ..core.services import ServiceHub

FIELDS = ["value", "type", "severity", "risk_score", "confidence", "country",
          "asn", "asn_name", "tags", "first_seen", "last_seen"]


def export_indicators_csv(path: Path, ids: list[int] | None = None) -> int:
    """Export indicators to CSV; pass ``ids`` to export only those rows."""
    hub = ServiceHub.get()
    if ids:
        inds = [hub.repo.get_indicator(i) for i in ids]
        inds = [i for i in inds if i]
    else:
        inds = hub.repo.search_indicators(limit=10000)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for ind in inds:
            row = {k: ind.get(k, "") for k in FIELDS}
            row["tags"] = ",".join(ind.get("tags") or [])
            writer.writerow(row)
    return len(inds)


def import_indicators_csv(path: Path) -> tuple[int, int]:
    """Import a CSV of indicators; runs a demo/live analysis per row.

    Returns (imported, skipped).
    """
    hub = ServiceHub.get()
    imported = skipped = 0
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            value = (row.get("value") or "").strip()
            if not value:
                skipped += 1
                continue
            try:
                if hub.engine.lookup(value):
                    imported += 1
                else:
                    skipped += 1
            except Exception:  # noqa: BLE001
                skipped += 1
    return imported, skipped
