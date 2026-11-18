#!/usr/bin/env python3
"""Probe: capture dashboard top and scrolled-bottom for visual QA."""
import os
import sys

sys.path.insert(0, "src")
sys.path.insert(0, ".")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer

from aegisx.application import create_application
from aegisx.core.services import init_services


def main() -> int:
    app = create_application(["probe"])
    hub = init_services()
    hub.engine.demo_mode = True
    from scripts.screenshot import seed_demo
    seed_demo(hub)
    from aegisx.ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1440, 880)
    win.show()
    page = win.page("dashboard")

    def grab1():
        app.processEvents()
        win.grab().save("/tmp/aegisx-qa/top.png", "PNG")
        print("saved top")
        page.page_scroll.verticalScrollBar().setValue(
            page.page_scroll.verticalScrollBar().maximum())
        QTimer.singleShot(700, grab2)

    def grab2():
        app.processEvents()
        win.grab().save("/tmp/aegisx-qa/bottom.png", "PNG")
        print("saved bottom")
        app.quit()

    os.makedirs("/tmp/aegisx-qa", exist_ok=True)
    QTimer.singleShot(1100, grab1)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
