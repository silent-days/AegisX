"""
AegisX — sidebar navigation.

Grouped navigation with animated selection indicator, hover states, brand
block and live system status footer (database + mode chips).
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    QRectF,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..styles import theme
from ..version import APP_NAME, APP_TAGLINE, APP_VERSION
from .components import label
from .icons import icon
from .logo import paint_shield

# (key, icon, label)  grouped by section
NAV_SECTIONS: list[tuple[str, list[tuple[str, str, str]]]] = [
    ("Overview", [
        ("dashboard", "dashboard", "Dashboard"),
        ("global_map", "globe", "Global Threat Map"),
    ]),
    ("Intelligence", [
        ("threat_intelligence", "database", "Threat Intelligence"),
        ("ip_investigation", "target", "IP Investigation"),
        ("domain_intelligence", "link", "Domain Intelligence"),
    ]),
    ("Analysis", [
        ("infrastructure", "server", "Infrastructure Analysis"),
        ("correlation", "share", "Threat Correlation"),
        ("campaigns", "flag", "Campaign Intelligence"),
        ("analytics", "analytics", "Threat Analytics"),
    ]),
    ("Workspace", [
        ("investigations", "briefcase", "Investigation Workspace"),
        ("sources", "database", "Intelligence Sources"),
        ("reports", "report", "Reports"),
    ]),
    ("System", [
        ("settings", "settings", "Settings"),
        ("about", "info", "About AegisX"),
    ]),
]


class NavButton(QPushButton):
    def __init__(self, key: str, icon_name: str, text: str) -> None:
        super().__init__(f" {text}")
        self.key = key
        self._icon_name = icon_name
        self.setObjectName("SidebarNavButton")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(38)
        self.setIcon(icon(icon_name, theme.COLORS["text_secondary"]))
        self.setIconSize(icon(icon_name).actualSize(self.iconSize()).expandedTo(self.iconSize()))
        self._apply_color(theme.COLORS["text_secondary"])

    def _apply_color(self, color: str) -> None:
        self.setIcon(icon(self._icon_name, color))
        self.setStyleSheet(self._style(color))

    def _style(self, color: str) -> str:
        return f"""
            QPushButton#SidebarNavButton {{
                color: {color};
                border: 0; border-radius: 10px; padding: 8px 12px; text-align: left;
                font-size: 13px; background: transparent;
            }}
        """

    def enterEvent(self, e) -> None:  # noqa: N802
        if not self.isChecked():
            self._apply_color(theme.COLORS["text"])
            self.setStyleSheet(self._style(theme.COLORS["text"]) +
                               "QPushButton#SidebarNavButton:hover { background: #F1F5F9; }")
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        if not self.isChecked():
            self._apply_color(theme.COLORS["text_secondary"])
        super().leaveEvent(e)

    def set_checked_state(self, checked: bool) -> None:
        self.setChecked(checked)
        if checked:
            self._apply_color(theme.COLORS["primary_dark"])
            self.setStyleSheet(self._style(theme.COLORS["primary_dark"]) +
                               f"QPushButton#SidebarNavButton:checked {{ background: {theme.COLORS['hover']};"
                               " font-weight: 650; }")
        else:
            self._apply_color(theme.COLORS["text_secondary"])


class Sidebar(QFrame):
    """Main navigation sidebar."""

    navigate = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(238)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # brand block
        brand = QWidget()
        bl = QHBoxLayout(brand)
        bl.setContentsMargins(18, 20, 18, 14)
        bl.setSpacing(12)
        from .components import _BrandLogo

        logo = _BrandLogo(40)
        bl.addWidget(logo)
        col = QVBoxLayout()
        col.setSpacing(1)
        col.addWidget(label(APP_NAME, "BrandTitle", wordwrap=False))
        sub = label(APP_TAGLINE.upper(), "BrandSub", wordwrap=False)
        col.addWidget(sub)
        bl.addLayout(col)
        outer.addWidget(brand)

        # nav scroll
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setStyleSheet("QScrollArea { border: 0; }")
        inner = QWidget()
        self.nav_lay = QVBoxLayout(inner)
        self.nav_lay.setContentsMargins(12, 8, 12, 8)
        self.nav_lay.setSpacing(4)

        self.buttons: dict[str, NavButton] = {}
        for section, items in NAV_SECTIONS:
            head = label(section.upper(), "SidebarGroup", wordwrap=False)
            head.setContentsMargins(6, 12, 0, 2)
            self.nav_lay.addWidget(head)
            for key, icon_name, text in items:
                btn = NavButton(key, icon_name, text)
                btn.clicked.connect(lambda _=False, k=key: self.navigate.emit(k))
                self.nav_lay.addWidget(btn)
                self.buttons[key] = btn
        self.nav_lay.addStretch(1)
        area.setWidget(inner)
        outer.addWidget(area, 1)

        # status footer
        footer = QFrame()
        footer.setStyleSheet(
            f"background: {theme.COLORS['surface']}; "
            f"border-top: 1px solid {theme.COLORS['divider']};"
        )
        fl = QVBoxLayout(footer)
        fl.setContentsMargins(16, 12, 16, 14)
        fl.setSpacing(7)

        self.db_row = self._status_row(theme.COLORS["success"], "Database connected")
        fl.addLayout(self.db_row)
        self.mode_row = self._status_row(theme.COLORS["warning"], "Demonstration mode")
        fl.addLayout(self.mode_row)

        ver = label(f"{APP_NAME} v{APP_VERSION} · Silent Days", "Muted", wordwrap=False)
        fl.addWidget(ver)
        outer.addWidget(footer)

        # animated selection indicator
        self._indicator = SelectionBar(self)
        self._indicator.raise_()
        self._slide = QPropertyAnimation(self._indicator, b"pos")
        self._slide.setDuration(220)
        self._slide.setEasingCurve(QEasingCurve.Type.OutCubic)

    # ------------------------------------------------------------------ api
    def set_active(self, key: str) -> None:
        for k, btn in self.buttons.items():
            btn.set_checked_state(k == key)
        target = self.buttons.get(key)
        if target:
            # account for scroll offset: map to sidebar coordinates
            top = target.mapTo(self, QPoint(0, 0)).y()
            self._slide.stop()
            self._slide.setStartValue(self._indicator.pos())
            self._slide.setEndValue(QPoint(10, top + 6))
            self._slide.start()

    def set_mode_status(self, demo: bool, db_ok: bool = True) -> None:
        self._set_row(self.mode_row, theme.COLORS["warning"] if demo else theme.COLORS["success"],
                      "Demonstration mode" if demo else "Live intelligence mode")
        self._set_row(self.db_row, theme.COLORS["success"] if db_ok else theme.COLORS["critical"],
                      "Database connected" if db_ok else "Database unavailable")

    # -------------------------------------------------------------- internal
    @staticmethod
    def _status_row(color: str, text: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)
        dot = QLabel()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
        dot.setObjectName("statusDot")
        row.addWidget(dot)
        lbl = label(text, "Muted", wordwrap=False)
        lbl.setStyleSheet(
            f"font-size: 11px; color: {theme.COLORS['text_secondary']};"
        )
        row.addWidget(lbl, 1)
        row.setProperty("dot", dot)
        row.setProperty("lbl", lbl)
        return row

    @staticmethod
    def _set_row(row: QHBoxLayout, color: str, text: str) -> None:
        dot = row.property("dot")
        lbl = row.property("lbl")
        if dot:
            dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
        if lbl:
            lbl.setText(text)

    def _paint_logo(self, e) -> None:  # type: ignore[override]
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        paint_shield(p, QRectF(0, 0, 40, 40), size=40)
        p.end()


class SelectionBar(QWidget):
    """Animated red pill highlighting the active nav item."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setFixedSize(3, 26)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(theme.COLORS["primary"]))
        p.drawRoundedRect(QRectF(0, 0, 3, 26), 1.5, 1.5)
