#!/usr/bin/env python3
"""QA capture v1.2: splash, dashboard (top/bottom), threat intelligence page."""
import os
import sys
import traceback

sys.path.insert(0, "src")
sys.path.insert(0, ".")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer

from aegisx.application import create_application
from aegisx.core.services import init_services


def step(fn):
    """Wrap a capture stage so failures print and the app still exits."""
    def wrapped():
        try:
            print(f"[qa] {fn.__name__}", flush=True)
            fn()
        except Exception:
            traceback.print_exc()
            QTimer.singleShot(200, app.quit)
    return wrapped


def main() -> int:
    global app
    app = create_application(["probe"])
    hub = init_services()
    hub.engine.demo_mode = True
    from scripts.screenshot import seed_demo
    seed_demo(hub)
    print("[qa] services ready", flush=True)

    from aegisx.ui.main_window import MainWindow
    from aegisx.ui.splash_screen import SplashScreen

    out = "/tmp/aegisx-qa"
    os.makedirs(out, exist_ok=True)

    splash = SplashScreen(min_ms=1000)
    splash.center_on_screen()
    splash.show()

    win = MainWindow()

    def grab_splash():
        app.processEvents()
        splash.grab().save(f"{out}/splash.png", "PNG")
        print("saved splash", flush=True)

    def show_main():
        splash.finish()
        win.show()
        win.raise_()

    def grab_dash_top():
        app.processEvents()
        win.grab().save(f"{out}/dash_top.png", "PNG")
        print("saved dash_top", flush=True)
        page = win.page("dashboard")
        sb = page.page_scroll.verticalScrollBar()
        sb.setValue(sb.maximum())
        QTimer.singleShot(700, grab_dash_bottom)

    def grab_dash_bottom():
        app.processEvents()
        win.grab().save(f"{out}/dash_bottom.png", "PNG")
        print("saved dash_bottom", flush=True)
        page = win.page("dashboard")
        page.page_scroll.verticalScrollBar().setValue(0)
        win.navigate("threat_intelligence")
        QTimer.singleShot(700, grab_ti)

    def grab_ti():
        app.processEvents()
        ti = win.page("threat_intelligence")
        ti.table.selectRow(0)
        ti.table.selectRow(1)
        app.processEvents()
        win.grab().save(f"{out}/threat_intel.png", "PNG")
        print("saved threat_intel", flush=True)
        ti.btn_adv.setChecked(True)
        QTimer.singleShot(400, grab_ti_adv)

    def grab_ti_adv():
        app.processEvents()
        win.grab().save(f"{out}/threat_intel_adv.png", "PNG")
        print("saved threat_intel_adv", flush=True)
        app.quit()

    # watchdog — never hang
    def watchdog():
        print("[qa] WATCHDOG TIMEOUT", flush=True)
        app.quit()

    QTimer.singleShot(700, step(grab_splash))
    QTimer.singleShot(1600, step(show_main))
    QTimer.singleShot(2700, step(grab_dash_top))
    QTimer.singleShot(30000, step(watchdog))
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
