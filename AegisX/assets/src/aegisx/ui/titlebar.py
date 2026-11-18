"""
AegisX — custom title bar.

Frameless-window chrome: brand mark, global threat search, notification
bell with event dropdown, window controls (min / max / close) and full
drag support. Close hover uses the brand red.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..styles import theme
from ..version import APP_NAME, APP_VERSION
from .components import IconButton, label
from .icons import icon
from .logo import paint_shield


class TitleBar(QFrame):
    """Application title bar (also serves as the frameless drag handle)."""

    minimize_clicked = Signal()
    maximize_clicked = Signal()
    close_clicked = Signal()
    search_requested = Signal(str)
    show_notifications = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setFixedHeight(48)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 0, 0)
        lay.setSpacing(10)

        # brand
        self._brand = BrandMark(self)
        lay.addWidget(self._brand)

        name_col = QVBoxLayout()
        name_col.setSpacing(0)
        t = label(APP_NAME, "BrandTitle", wordwrap=False)
        name_col.addWidget(t)
        lay.addLayout(name_col)

        chip = label(f"v{APP_VERSION}", "Muted", wordwrap=False)
        chip.setStyleSheet(
            f"background: {theme.COLORS['primary_soft']}; color: {theme.COLORS['primary_dark']};"
            f"border-radius: 8px; padding: 2px 8px; font-size: 10.5px; font-weight: 700;"
        )
        lay.addWidget(chip)

        lay.addStretch(1)

        # global search
        self.search = QLineEdit()
        self.search.setObjectName("TitleSearch")
        self.search.setPlaceholderText("Search indicators, IPs, domains, hashes…   (Enter)")
        self.search.setFixedWidth(420)
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(
            lambda: self.search_requested.emit(self.search.text().strip())
        )
        lay.addWidget(self.search)

        lay.addStretch(1)

        # notifications
        self.bell = IconButton("bell", tip="Recent activity")
        self.bell.clicked.connect(self.show_notifications.emit)
        lay.addWidget(self.bell)

        # window controls
        self.btn_min = IconButton("minus", tip="Minimize")
        self.btn_min.setFixedSize(40, 44)
        self.btn_min.clicked.connect(self.minimize_clicked.emit)
        lay.addWidget(self.btn_min)

        self.btn_max = IconButton("square", tip="Maximize")
        self.btn_max.setFixedSize(40, 44)
        self.btn_max.clicked.connect(self.maximize_clicked.emit)
        lay.addWidget(self.btn_max)

        self.btn_close = IconButton("x", tip="Close")
        self.btn_close.setFixedSize(40, 44)
        self.btn_close.setStyleSheet("IconButton { border-radius: 0; }")
        self.btn_close.clicked.connect(self.close_clicked.emit)
        lay.addWidget(self.btn_close)

        self._drag_pos = None

    # ------------------------------------------------------------ dragging
    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            if event.position().y() > 44 or self._hit_child(event.position()):
                event.ignore()
                return
            self._drag_pos = event.globalPosition().toPoint() - self.window().frameGeometry().topLeft()
        super().mousePressEvent(event)

    def _hit_child(self, pos: QPointF) -> bool:
        for w in (self.search, self.bell, self.btn_min, self.btn_max, self.btn_close):
            if w.underMouse():
                return True
        return False

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if self._drag_pos is not None and event.buttons() & Qt.MouseButton.LeftButton:
            win = self.window()
            if win.isMaximized():
                win.showNormal()
            new = event.globalPosition().toPoint() - self._drag_pos
            win.move(new)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, _event) -> None:  # noqa: N802
        self._drag_pos = None

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802
        if not self._hit_child(event.position()):
            self.maximize_clicked.emit()
        super().mouseDoubleClickEvent(event)


class BrandMark(QWidget):
    """Small painted shield + globe accent for the title bar."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(34, 34)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        paint_shield(p, QRectF(1, 1, 32, 32), size=32)


class NotificationPanel(QFrame):
    """Dropdown listing recent platform events (real event-bus history)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedWidth(360)
        self.setStyleSheet(
            "QFrame#Card { background: "
            f"{theme.COLORS['surface']}; border: 1px solid "
            f"{theme.COLORS['border']}; border-radius: 12px; }}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 12)
        head = label("Recent Activity", "H3", wordwrap=False)
        lay.addWidget(head)
        self.list_area = QScrollArea()
        self.list_area.setWidgetResizable(True)
        self.list_area.setFixedHeight(280)
        inner = QWidget()
        self._list = QVBoxLayout(inner)
        self._list.setContentsMargins(0, 4, 0, 4)
        self._list.setSpacing(8)
        self.list_area.setWidget(inner)
        lay.addWidget(self.list_area)

    def set_events(self, events) -> None:
        while self._list.count():
            item = self._list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not events:
            self._list.addWidget(label("No recent activity.", "Muted"))
            return
        sev_colors = {"critical": theme.COLORS["sev_critical"],
                      "high": theme.COLORS["sev_high"],
                      "medium": theme.COLORS["sev_medium"],
                      "warning": theme.COLORS["sev_medium"],
                      "low": theme.COLORS["sev_low"],
                      "info": theme.COLORS["info"],
                      "success": theme.COLORS["success"]}
        for ev in events[:14]:
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(4, 4, 4, 4)
            rl.setSpacing(8)
            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(
                f"background: {sev_colors.get(ev.severity, theme.COLORS['info'])};"
                f"border-radius: 4px;"
            )
            rl.addWidget(dot)
            msg = label(ev.message, "", wordwrap=True)
            msg.setStyleSheet(
                f"font-size: 11.5px; color: {theme.COLORS['text']};"
            )
            msg.setWordWrap(True)
            rl.addWidget(msg, 1)
            self._list.addWidget(row)
        self._list.addStretch(1)
