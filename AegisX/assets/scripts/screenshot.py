#!/usr/bin/env python3
"""
AegisX — headless screenshot generator.

Runs the application offscreen, seeds demonstration data, navigates every
page and captures genuine screenshots for the README and visual QA.

Usage:  QT_QPA_PLATFORM=offscreen python scripts/screenshot.py [outdir]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for p in (str(SRC), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "assets" / "screenshots"
OUT.mkdir(parents=True, exist_ok=True)

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from aegisx.application import create_application  # noqa: E402
from aegisx.core.services import init_services  # noqa: E402
from aegisx.utils.logger import setup_logging  # noqa: E402


def seed_demo(hub) -> None:
    """Populate a rich demo corpus for realistic screenshots."""
    from aegisx.utils.demo_data import DEMO_CAMPAIGNS, DEMO_INVESTIGATIONS

    ips = [f"192.0.2.{i}" for i in range(3, 40)] + \
          [f"198.51.100.{i}" for i in range(1, 20)] + \
          [f"203.0.113.{i}" for i in range(1, 16)]
    domains = ["secure-login.example", "vault-update.example", "cdn-sync.example",
               "mail-portal.example", "api-gateway.example", "pay-verify.example",
               "node-backup.example", "cloud-auth.example", "verify-account.example",
               "update-service.example"]
    values = ips + domains
    for i, v in enumerate(values):
        hub.engine.lookup(v)
        if i % 12 == 0:
            hub.repo.add_event("lookup", f"Analyzed {v} in background batch",
                               severity="info")

    # Spread last_seen across the last 30 days so the activity timeline shows
    # a realistic 30-day curve (demo data only).
    from aegisx.database.repository import iso, utcnow
    from datetime import timedelta

    inds = hub.repo.search_indicators(limit=500)
    for j, ind in enumerate(inds):
        days_back = (j * 29) // max(1, len(inds))
        new_ts = iso(utcnow() - timedelta(days=29 - days_back,
                                          hours=(j * 7) % 24))
        hub.repo._x("UPDATE indicators SET last_seen=?, first_seen=? WHERE id=?",
                    (new_ts, new_ts, ind["id"]))

    for camp in DEMO_CAMPAIGNS:
        cid = hub.repo.upsert_campaign(
            camp["name"], description=camp["description"], severity=camp["severity"],
            confidence=camp["confidence"], attribution=camp["attribution"],
            attribution_confidence=camp["attribution_confidence"],
            tags=camp["tags"], mitre=camp["mitre"], demo=True)
        # link 5-8 related demo indicators
        for v in values[(hash(camp["name"]) % 20)::6][:7]:
            ind = hub.repo.get_indicator_by_value(v)
            if ind:
                hub.repo.link_campaign_indicator(cid, ind["id"])

    for inv in DEMO_INVESTIGATIONS:
        inv_id = hub.repo.create_investigation(inv["name"],
                                               description=inv["description"],
                                               priority=inv["priority"])
        hub.repo.update_investigation(inv_id, status=inv["status"])
        for v in values[:6]:
            ind = hub.repo.get_indicator_by_value(v)
            if ind:
                hub.repo.add_investigation_item(inv_id, ind["id"])
        hub.repo.add_note(inv_id, "Security Researcher", "Initial triage completed.")

    hub.repo.add_event("session", "Demonstration dataset loaded", severity="success")


def main() -> int:
    setup_logging()
    app = create_application(["aegisx-screenshots"])
    hub = init_services()
    hub.engine.demo_mode = True

    seed_demo(hub)

    from aegisx.ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1440, 880)
    win.show()

    shots = [
        ("dashboard", "dashboard", 900),
        ("global_map", "global_map", 900),
        ("ip_investigation", "ip_investigation", 900),
        ("threat_intelligence", "threat_intelligence", 700),
        ("correlation", "correlation", 700),
        ("campaigns", "campaigns", 700),
        ("analytics", "analytics", 900),
        ("infrastructure", "infrastructure", 700),
        ("investigations", "investigations", 700),
        ("sources", "sources", 700),
        ("domain_intelligence", "domain_intelligence", 700),
        ("reports", "reports", 600),
        ("settings", "settings", 700),
        ("about", "about", 700),
    ]
    state = {"idx": 0}

    def step():
        idx = state["idx"]
        if idx >= len(shots):
            app.quit()
            return
        key, name, delay = shots[idx]
        state["idx"] = idx + 1
        try:
            win.navigate(key)
            if key == "ip_investigation":
                page = win.page("ip_investigation")
                page.set_input("192.0.2.7")
                page.run_lookup()
            if key == "global_map":
                page = win.page("global_map")
                page._toggle_demo_feed()
        except Exception as e:  # noqa: BLE001
            print(f"NAV-FAIL {key}: {e}", file=sys.stderr)
        app.processEvents()

        def grab():
            app.processEvents()
            try:
                pix = win.grab()
                pix.save(str(OUT / f"{name}.png"), "PNG")
                print(f"saved {name}.png")
            except Exception as e:  # noqa: BLE001
                print(f"GRAB-FAIL {key}: {e}", file=sys.stderr)
            QTimer.singleShot(180, step)

        QTimer.singleShot(delay, grab)

    QTimer.singleShot(600, step)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
