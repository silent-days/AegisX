"""
AegisX — main window.

Frameless application shell: custom title bar, sidebar navigation with
animated page transitions (fade + slide), toast notifications, event-bus
bridging and edge resize handling.
"""

from __future__ import annotations

import logging

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QRect,
    Qt,
    QTimer,
)
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.services import ServiceHub
from ..styles import theme
from .components import add_shadow, label
from .icons import icon
from .notifications import ToastHost
from .pages import PAGE_SPECS
from .sidebar import Sidebar
from .titlebar import NotificationPanel, TitleBar

log = logging.getLogger("aegisx.ui")

RESIZE_MARGIN = 6


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AegisX — Global Cyber Threat Intelligence")
        self.setMinimumSize(1180, 720)
        self.resize(1440, 880)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setMouseTracking(True)

        self.hub: ServiceHub = ServiceHub.get()

        # root layout -------------------------------------------------------
        central = QWidget()
        central.setObjectName("RootSurface")
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.titlebar = TitleBar()
        self.titlebar.minimize_clicked.connect(self.showMinimized)
        self.titlebar.maximize_clicked.connect(self._toggle_maximize)
        self.titlebar.close_clicked.connect(self.close)
        self.titlebar.search_requested.connect(self._global_search)
        self.titlebar.show_notifications.connect(self._toggle_notifications)
        outer.addWidget(self.titlebar)

        body = QWidget()
        body_lay = QHBoxLayout(body)
        body_lay.setContentsMargins(0, 0, 0, 0)
        body_lay.setSpacing(0)

        self.sidebar = Sidebar()
        self.sidebar.navigate.connect(self.navigate)
        body_lay.addWidget(self.sidebar)

        # content stack with fade transitions
        self.stack = QStackedWidget()
        self.content_wrap = QWidget()
        content_lay = QVBoxLayout(self.content_wrap)
        content_lay.setContentsMargins(0, 0, 0, 0)
        content_lay.addWidget(self.stack, 1)
        body_lay.addWidget(self.content_wrap, 1)

        outer.addWidget(body, 1)

        # status strip -------------------------------------------------------
        status = QLabel("")
        status.setObjectName("StatusStrip")
        status.setFixedHeight(26)
        status.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        status.setStyleSheet("padding-right: 14px; color: #94A3B8; font-size: 11px;")
        outer.addWidget(status)
        self.status_lbl = status

        # pages (lazy) -------------------------------------------------------
        self._pages: dict[str, object] = {}
        self._specs = {spec.key: spec for spec in PAGE_SPECS}
        self._toasts = ToastHost(self)
        self._notif_panel: NotificationPanel | None = None
        self._transition_anim: QPropertyAnimation | None = None

        # event bus -> toasts ------------------------------------------------
        self.hub.events.subscribe_all(self._on_event)

        # initial page
        self.navigate("dashboard")
        self.sidebar.set_mode_status(demo=self.hub.demo_mode)

        # periodic refresh of the visible page
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(30_000)
        self._refresh_timer.timeout.connect(self._refresh_visible)
        self._refresh_timer.start()

    # ---------------------------------------------------------------- pages
    def page(self, key: str):
        return self._pages.get(key)

    def navigate(self, key: str) -> None:
        if key not in self._specs:
            return
        spec = self._specs[key]
        created = False
        if key not in self._pages:
            widget = spec.factory()
            self.stack.addWidget(widget)
            self._pages[key] = widget
            created = True

        target = self._pages[key]
        previous = self.stack.currentWidget()
        if previous is target and not created:
            target.refresh()
            return

        self.stack.setCurrentWidget(target)
        self.sidebar.set_active(key)
        self.status_lbl.setText(f"{spec.title} · AegisX")

        # smooth fade+slide transition
        effect = QGraphicsOpacityEffect(target)
        target.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity")
        anim.setDuration(240)
        anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        anim.setStartValue(0.25)
        anim.setEndValue(1.0)
        anim.finished.connect(lambda: target.setGraphicsEffect(None))
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        self._transition_anim = anim

        try:
            target.refresh()
        except Exception:  # noqa: BLE001
            log.exception("Page %s refresh failed", key)

    def _refresh_visible(self) -> None:
        widget = self.stack.currentWidget()
        if widget is None or not self.isVisible():
            return
        try:
            widget.refresh()
        except Exception:  # noqa: BLE001
            log.exception("Periodic refresh failed")

    # ------------------------------------------------------------- search
    def _global_search(self, query: str) -> None:
        if not query:
            return
        self.navigate("threat_intelligence")
        page = self.page("threat_intelligence")
        if page:
            page.search.setText(query)
            page.refresh(reset_page=True)

    # ------------------------------------------------------- notifications
    def _on_event(self, event) -> None:
        # Only surface notable events as toasts (keep UI calm).
        notable = event.kind in (
            "lookup.completed", "lookup.no_sources", "source.error", "report.generated",
            "cache.cleared", "mode.changed", "mode.warn", "investigation.created",
            "db.wiped", "campaign.created", "campaign.deleted",
            "indicator.deleted", "indicators.bulk_deleted",
        )
        if notable:
            QTimer.singleShot(0, lambda: self._toast(event))

    def _toast(self, event) -> None:
        kind = event.severity if event.severity in ("success", "warning", "critical") else "info"
        self._toasts.notify(kind, _TITLE_BY_KIND.get(kind, "AegisX"), event.message[:160])

    def _toggle_notifications(self) -> None:
        if self._notif_panel is not None:
            self._notif_panel.deleteLater()
            self._notif_panel = None
            return
        panel = NotificationPanel(self)
        add_shadow(panel, blur=30, alpha=40, y_offset=8)
        panel.set_events(self.hub.events.recent(20))
        anchor = self.titlebar.bell.mapTo(self, QPoint(0, self.titlebar.bell.height()))
        panel.move(anchor.x() - panel.width() + self.titlebar.bell.width() + 40, 54)
        panel.show()
        panel.raise_()
        self._notif_panel = panel

    def update_mode_status(self) -> None:
        self.sidebar.set_mode_status(demo=self.hub.demo_mode)

    # ------------------------------------------------------------ frameless
    def _toggle_maximize(self) -> None:
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def resizeEvent(self, e) -> None:  # noqa: N802
        self._toasts.resize(self.size())
        if self._notif_panel is not None:
            self._notif_panel.deleteLater()
            self._notif_panel = None
        super().resizeEvent(e)

    def mousePressEvent(self, e) -> None:  # noqa: N802
        # edge resize grips for the frameless window
        if e.button() == Qt.MouseButton.LeftButton:
            edge = self._edge_at(e.position().toPoint())
            if edge:
                self.windowHandle().startSystemResize(edge)
                return
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        edge = self._edge_at(e.position().toPoint())
        if edge and not self.isMaximized():
            cursors = {
                Qt.Edge.LeftEdge: Qt.CursorShape.SizeHorCursor,
                Qt.Edge.RightEdge: Qt.CursorShape.SizeHorCursor,
                Qt.Edge.TopEdge: Qt.CursorShape.SizeVerCursor,
                Qt.Edge.BottomEdge: Qt.CursorShape.SizeVerCursor,
            }
            if edge in cursors:
                self.setCursor(cursors[edge])
        else:
            self.setCursor(Qt.CursorShape.ArrowCursor)
        super().mouseMoveEvent(e)

    def _edge_at(self, pos: QPoint):
        r = self.rect()
        m = RESIZE_MARGIN
        edge = Qt.Edge(0)
        if pos.x() <= m:
            edge |= Qt.Edge.LeftEdge
        if pos.x() >= r.width() - m:
            edge |= Qt.Edge.RightEdge
        if pos.y() <= m:
            edge |= Qt.Edge.TopEdge
        if pos.y() >= r.height() - m:
            edge |= Qt.Edge.BottomEdge
        return edge or None

    # ------------------------------------------------------------- shutdown
    def closeEvent(self, e) -> None:  # noqa: N802
        self.hub.events.publish("app.shutdown", "AegisX session closed", severity="info")
        self._refresh_timer.stop()
        super().closeEvent(e)


_TITLE_BY_KIND = {"success": "Success", "warning": "Attention", "critical": "Critical"}
