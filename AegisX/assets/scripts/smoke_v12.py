#!/usr/bin/env python3
"""Smoke test v1.2: visit every page, catch exceptions, report."""
import os
import sys
import traceback

sys.path.insert(0, "src")
sys.path.insert(0, ".")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer

from aegisx.application import create_application
from aegisx.core.services import init_services


def main() -> int:
    app = create_application(["smoke"])
    hub = init_services()
    hub.engine.demo_mode = True
    from scripts.screenshot import seed_demo
    seed_demo(hub)
    from aegisx.ui.main_window import MainWindow

    win = MainWindow()
    win.show()

    pages = [spec.key for spec in __import__(
        "aegisx.ui.pages", fromlist=["PAGE_SPECS"]).PAGE_SPECS]
    cursor = {"i": 0, "errors": []}

    def visit_next():
        if cursor["i"] >= len(pages):
            finish()
            return
        key = pages[cursor["i"]]
        cursor["i"] += 1
        try:
            win.navigate(key)
            print(f"[smoke] {key}: OK", flush=True)
        except Exception:
            cursor["errors"].append(key)
            print(f"[smoke] {key}: FAILED", flush=True)
            traceback.print_exc()
        QTimer.singleShot(120, visit_next)

    def finish():
        if cursor["errors"]:
            print("[smoke] FAILED PAGES:", cursor["errors"], flush=True)
            app.exit(2)
        else:
            print("[smoke] ALL PAGES OK", flush=True)
            app.quit()

    QTimer.singleShot(900, visit_next)
    QTimer.singleShot(40000, finish)  # watchdog
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
