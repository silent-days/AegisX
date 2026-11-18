"""
AegisX — application bootstrap.

QApplication setup: theme, high-DPI policy, service initialization, boot
splash and main window lifecycle.
"""

from __future__ import annotations

import logging
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication

from .core.services import init_services
from .styles import apply as apply_theme
from .utils.logger import get_logger, setup_logging
from .utils.paths import load_env_file
from .version import APP_NAME, ORG_DOMAIN, ORG_NAME

log = get_logger("aegisx.app")


def create_application(argv: list[str]) -> QApplication:
    # Must be set before the QApplication instance exists.
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setOrganizationDomain(ORG_DOMAIN)
    app.setApplicationDisplayName(APP_NAME)
    app.setDesktopFileName("aegisx")
    QGuiApplication.setApplicationDisplayName(APP_NAME)

    # HiDPI: Qt6 enables scaling automatically; keep crisp rounding.
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    apply_theme(app)
    return app


def run(args: list[str]) -> int:
    """Application entry point (GUI path)."""
    load_env_file()
    setup_logging()
    log.info("Starting %s application", APP_NAME)

    app = create_application(args)

    # services (database + engines) must exist before UI pages construct
    hub = init_services()

    # Import here (after QApplication) so Qt plugins are ready.
    from .ui.main_window import MainWindow
    from .ui.splash_screen import SplashScreen

    splash = SplashScreen(min_ms=600)
    screen = QGuiApplication.primaryScreen()
    if screen:
        splash.move(screen.availableGeometry().center() - splash.rect().center())
    splash.show()
    app.processEvents()

    window: MainWindow | None = None

    def _construct() -> None:
        nonlocal window
        try:
            window = MainWindow()
        except Exception:  # noqa: BLE001
            log.exception("Main window construction failed")
            splash.close()
            raise

    QTimer.singleShot(50, _construct)

    def _show_main() -> None:
        nonlocal window
        if window is None:
            QTimer.singleShot(60, _show_main)
            return
        if "--maximized" not in args:
            screen = window.screen() or QGuiApplication.primaryScreen()
            if screen:
                window.move(screen.availableGeometry().center() - window.rect().center())
        splash.finish()
        window.showMaximized() if "--maximized" in args else window.show()
        log.info("Main window displayed")

    # show the window as soon as the splash minimum display time passed
    QTimer.singleShot(650, _show_main)
    splash.finished.connect(lambda: None)

    exit_code = 0
    try:
        exit_code = app.exec()
    except Exception:  # noqa: BLE001
        log.exception("Fatal error in event loop")
        raise
    finally:
        try:
            hub.repo.close()
        except Exception:  # noqa: BLE001
            pass
    return exit_code
