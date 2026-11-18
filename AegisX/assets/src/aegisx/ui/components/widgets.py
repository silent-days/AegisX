"""
AegisX — reusable UI components.

Premium light-theme widget library used across every page: cards, stat
cards, badges, buttons, search inputs, banners, loaders, data tables,
section headers, empty states and toasts.
"""

from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import (
    QEasingCurve,
    QRectF,
    Qt,
    QTimer,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLayout,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ..icons import icon
from ..logo import paint_shield

APP_MOTTO = "Secure · Analyze · Investigate · Protect"


class _BrandLogo(QLabel):
    """Painted shield mark usable from any component."""

    def __init__(self, size: int) -> None:
        super().__init__()
        self._size = size
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        paint_shield(p, QRectF(0, 0, self._size, self._size), size=self._size - 2)
        p.end()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------ shadow
def add_shadow(widget: QWidget, blur: int = 16, alpha: int = 22,
               y_offset: int = 3) -> None:
    effect = QGraphicsDropShadowEffect(widget)
    color = QColor(17, 24, 39, alpha)
    effect.setBlurRadius(blur)
    effect.setOffset(0, y_offset)
    effect.setColor(color)
    widget.setGraphicsEffect(effect)


# -------------------------------------------------------------------- card
class Card(QFrame):
    """Rounded white surface with subtle border + optional soft shadow."""

    def __init__(self, *, shadow: bool = True, interactive: bool = False,
                 flat: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("CardInteractive" if interactive else ("CardFlat" if flat else "Card"))
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(16, 14, 16, 14)
        self._lay.setSpacing(10)
        if shadow and not flat:
            add_shadow(self, blur=18, alpha=18, y_offset=2)

    def layout(self) -> QVBoxLayout:  # type: ignore[override]
        return self._lay

    def add(self, widget: QWidget, stretch: int = 0) -> None:
        self._lay.addWidget(widget, stretch)


def hspacer() -> QWidget:
    w = QWidget()
    w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    return w


def vspacer() -> QWidget:
    w = QWidget()
    w.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
    return w


def hline() -> QFrame:
    f = QFrame()
    f.setFixedHeight(1)
    f.setStyleSheet(f"background: {theme.COLORS['divider']}; border: 0;")
    return f


# ------------------------------------------------------------------- text
def label(text: str, style: str = "", *, wordwrap: bool = True) -> QLabel:
    lbl = QLabel(text)
    if style:
        lbl.setObjectName(style)
    lbl.setWordWrap(wordwrap)
    return lbl


def section_header(title: str, subtitle: str = "", *, actions: QWidget | None = None) -> QWidget:
    """Page-level header: big title + subtitle + optional right actions."""
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    left = QVBoxLayout()
    left.setSpacing(3)
    t = label(title, "H1", wordwrap=False)
    s = label(subtitle, "Subtitle", wordwrap=False) if subtitle else None
    left.addWidget(t)
    if s:
        left.addWidget(s)
    lay.addLayout(left)
    lay.addStretch(1)
    if actions:
        lay.addWidget(actions)
    return w


# ------------------------------------------------------------------ badges
SEV_LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
              "low": "LOW", "info": "INFO"}


class Badge(QLabel):
    KINDS = ("critical", "high", "medium", "low", "info", "success", "demo", "primary")

    def __init__(self, text: str, kind: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(text.upper() if kind in SEV_LABELS else text, parent)
        kind = kind if kind in self.KINDS else "info"
        self.setObjectName(f"Badge{kind.capitalize()}")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


def severity_badge(sev: str) -> Badge:
    return Badge(SEV_LABELS.get(sev, sev.upper()), sev)


# ----------------------------------------------------------------- buttons
class PrimaryButton(QPushButton):
    def __init__(self, text: str, icon_name: str | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Primary")
        if icon_name:
            self.setIcon(icon(icon_name, "#FFFFFF"))
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class GhostButton(QPushButton):
    def __init__(self, text: str, icon_name: str | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Ghost")
        if icon_name:
            self.setIcon(icon(icon_name, theme.COLORS["text_secondary"]))
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class DangerButton(QPushButton):
    def __init__(self, text: str, icon_name: str | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("Danger")
        if icon_name:
            self.setIcon(icon(icon_name, theme.COLORS["critical"]))
        self.setCursor(Qt.CursorShape.PointingHandCursor)


class IconButton(QPushButton):
    def __init__(self, icon_name: str, *, color: str | None = None,
                 size: int = 18, tip: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        color = color or theme.COLORS["text_secondary"]
        self._icon_name, self._color, self._size = icon_name, color, size
        self.setIcon(icon(icon_name, color, size))
        self.setFixedSize(size + 20, size + 20)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        if tip:
            self.setToolTip(tip)

    def enterEvent(self, e) -> None:  # noqa: N802
        self.setIcon(icon(self._icon_name, theme.COLORS["primary"], self._size))
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        self.setIcon(icon(self._icon_name, self._color, self._size))
        super().leaveEvent(e)


# ------------------------------------------------------------------- stat
class StatCard(QFrame):
    """Animated dashboard metric card."""

    clicked = Signal()

    def __init__(self, title: str, value: int, *, icon_name: str = "activity",
                 accent: str | None = None, delta: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("CardInteractive")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        add_shadow(self, blur=16, alpha=16, y_offset=2)
        self._accent = accent or theme.COLORS["primary"]
        self._value = 0
        self._target = value

        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 14)
        lay.setSpacing(6)

        top = QHBoxLayout()
        ic = QLabel()
        ic.setPixmap(icon(icon_name, self._accent, 22).pixmap(22, 22))
        ic.setStyleSheet(
            f"background: {theme.rgba_hex(self._accent, 0.10)}; border-radius: 9px; padding: 8px;")
        top.addWidget(ic)
        top.addStretch(1)
        if delta:
            d = label(delta, "", wordwrap=False)
            d.setStyleSheet("color: #16A34A; font-size: 11px; font-weight: 700;")
            top.addWidget(d)
        lay.addLayout(top)

        self.value_lbl = label("0", "BigNumber", wordwrap=False)
        lay.addWidget(self.value_lbl)

        t = label(title, "Subtitle", wordwrap=False)
        lay.addWidget(t)
        lay.addStretch(1)

        self._anim = QVariantAnimation(self)
        self._anim.setDuration(900)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(lambda v: self.set_value(int(v)))

    def set_target(self, value: int) -> None:
        self._target = value
        self._anim.stop()
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(value)
        self._anim.start()

    def paintEvent(self, e) -> None:  # noqa: N802
        super().paintEvent(e)
        # accent line on top
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(self._accent))
        p.drawRoundedRect(QRectF(18, 0, 34, 3), 2, 2)

    def get_value(self) -> int:
        return self._value

    def set_value(self, v: int) -> None:
        self._value = int(v)
        self.value_lbl.setText(f"{self._value:,}")

    def mouseReleaseEvent(self, e) -> None:  # noqa: N802
        self.clicked.emit()
        super().mouseReleaseEvent(e)


# ------------------------------------------------------------------ banner
class Banner(QFrame):
    """Inline notice strip: info / warning / demo / success."""

    def __init__(self, text: str, kind: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        icons = {"info": "info", "warning": "alert", "demo": "alert",
                 "success": "check", "error": "alert"}
        colors = {
            "info": (theme.COLORS["info_soft"], theme.COLORS["info"], "#1E40AF"),
            "warning": (theme.COLORS["warning_soft"], theme.COLORS["warning"], "#92400E"),
            "demo": (theme.COLORS["warning_soft"], theme.COLORS["warning"], "#92400E"),
            "success": (theme.COLORS["success_soft"], theme.COLORS["success"], "#166534"),
            "error": (theme.COLORS["critical_soft"], theme.COLORS["critical"], "#991B1B"),
        }
        bg, border, fg = colors.get(kind, colors["info"])
        self.setStyleSheet(
            f"Banner {{ background: {bg}; border: 1px {'dashed' if kind == 'demo' else 'solid'} {border};"
            f" border-radius: 10px; }}"
        )
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 9, 12, 9)
        lay.setSpacing(10)
        ic = QLabel()
        ic.setPixmap(icon(icons.get(kind, "info"), fg, 16).pixmap(16, 16))
        lay.addWidget(ic)
        self._lbl = QLabel(text)
        self._lbl.setStyleSheet(f"color: {fg}; font-size: 12px; font-weight: 600; background: transparent;")
        self._lbl.setWordWrap(True)
        lay.addWidget(self._lbl, 1)

    def set_text(self, text: str) -> None:
        self._lbl.setText(text)

    def show_for(self, kind: str, text: str) -> None:
        new = Banner(text, kind, self.parentWidget())
        new.hide()
        self.hide()


# ----------------------------------------------------------------- spinner
class Spinner(QWidget):
    """Smooth rotating arc loader."""

    def __init__(self, size: int = 26, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._size = size
        self._angle = 0
        self.setFixedSize(size, size)
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)

    def _tick(self) -> None:
        self._angle = (self._angle + 6) % 360
        self.update()

    def start(self) -> None:
        self.show()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(3, 3, self._size - 6, self._size - 6)
        pen = QPen(QColor(theme.COLORS["divider"]), 3.2, Qt.PenStyle.SolidLine,
                   Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 0, 360 * 16)
        pen.setColor(QColor(theme.COLORS["primary"]))
        p.setPen(pen)
        p.drawArc(rect, (self._angle - 90) * 16, 100 * 16)


# ------------------------------------------------------------------ tables
class DataTable(QTableWidget):
    """Consistent, professional data table.

    Supports multi-row selection (``multi_select=True`` enables Ctrl/Shift
    selection with :meth:`selected_payloads`) and an optional trailing
    per-row action column (e.g. a quick Remove button on every row).
    """

    row_selected = Signal(dict)          # row data payload
    row_double = Signal(dict)
    row_action = Signal(dict, int)       # payload, action index
    selection_changed = Signal(int)      # number of selected payloads

    def __init__(self, headers: list[str], *, stretch_last: bool = True,
                 multi_select: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(0, len(headers), parent)
        self.setObjectName("DataTable")
        self.setHorizontalHeaderLabels(headers)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(
            QTableWidget.SelectionMode.ExtendedSelection if multi_select
            else QTableWidget.SelectionMode.SingleSelection)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setDefaultSectionSize(38)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.DefaultContextMenu)
        if stretch_last:
            self.horizontalHeader().setStretchLastSection(True)
        self._payloads: list[dict] = []
        self._action_specs: list[tuple[str, str]] = []   # (icon, tooltip)
        self.itemSelectionChanged.connect(self._emit_row)
        self.itemSelectionChanged.connect(self._emit_selection_count)

    def _emit_row(self) -> None:
        row = self.currentRow()
        if 0 <= row < len(self._payloads):
            self.row_selected.emit(self._payloads[row])

    def _emit_selection_count(self) -> None:
        self.selection_changed.emit(len(self.selected_payloads()))

    def mouseDoubleClickEvent(self, e) -> None:  # noqa: N802
        row = self.currentRow()
        if 0 <= row < len(self._payloads):
            self.row_double.emit(self._payloads[row])
        super().mouseDoubleClickEvent(e)

    def selected_payloads(self) -> list[dict]:
        """Payloads for every currently selected row (multi-select aware)."""
        out = []
        for r in sorted({i.row() for i in self.selectedIndexes()}):
            if 0 <= r < len(self._payloads):
                out.append(self._payloads[r])
        return out

    def select_all_rows(self) -> None:
        self.selectAll()

    def clear_selection(self) -> None:
        self.clearSelection()

    def set_rows(self, rows: list[list[str]], payloads: list[dict] | None = None,
                 actions: list[tuple[str, str]] | None = None) -> None:
        """Fill the table.

        ``actions`` is an optional list of ``(icon_name, tooltip)`` pairs
        rendered as small icon buttons in a trailing column on every row;
        clicking one emits ``row_action(payload, index)``.
        """
        self.setRowCount(0)
        self._payloads = payloads or [{} for _ in rows]
        self._action_specs = actions or []
        has_actions = bool(self._action_specs)
        if rows:
            target_cols = len(rows[0]) + (1 if has_actions else 0)
        else:
            target_cols = self.columnCount()
        if has_actions and target_cols > 0:
            if not self.horizontalHeaderItem(target_cols - 1) or \
                    not self.horizontalHeaderItem(target_cols - 1).text():
                self.setHorizontalHeaderItem(
                    target_cols - 1, QTableWidgetItem("Actions"))
        if self.columnCount() != target_cols:
            self.setColumnCount(target_cols)
        for r, row in enumerate(rows):
            self.insertRow(r)
            for c, text in enumerate(row):
                item = QTableWidgetItem(str(text))
                item.setToolTip(str(text))
                if c == 0:
                    f = item.font()
                    f.setBold(True)
                    item.setFont(f)
                self.setItem(r, c, item)
            if has_actions:
                host = QWidget()
                hl = QHBoxLayout(host)
                hl.setContentsMargins(4, 2, 4, 2)
                hl.setSpacing(4)
                hl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                for ai, (icon_name, tip) in enumerate(self._action_specs):
                    b = IconButton(icon_name, size=14, tip=tip)
                    b.setStyleSheet(
                        "IconButton { background: transparent; border: 1px solid transparent;"
                        " border-radius: 7px; }"
                        "IconButton:hover { background: #FEE2E2; border: 1px solid #FECACA; }")
                    b.clicked.connect(
                        lambda _c=False, rr=r: self._fire_action(rr))
                    hl.addWidget(b)
                host.setStyleSheet("background: transparent;")
                self.setCellWidget(r, target_cols - 1, host)
                item0 = self.item(r, 0)
                item0.setData(Qt.ItemDataRole.UserRole + 1, r)

    def _fire_action(self, row: int) -> None:
        if 0 <= row < len(self._payloads):
            self.row_action.emit(self._payloads[row], 0)

    def clear_rows(self) -> None:
        self.setRowCount(0)
        self._payloads = []


# --------------------------------------------------------------- empty state
class EmptyState(QWidget):
    def __init__(self, title: str, subtitle: str = "", icon_name: str = "search",
                 action: QPushButton | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 34, 20, 34)
        lay.setSpacing(8)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic = QLabel()
        ic.setPixmap(icon(icon_name, theme.COLORS["text_muted"], 40).pixmap(40, 40))
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(ic)
        t = label(title, "H3")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(t)
        s = label(subtitle, "Muted")
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(s)
        if action:
            wrap = QHBoxLayout()
            wrap.addStretch(1)
            wrap.addWidget(action)
            wrap.addStretch(1)
            lay.addLayout(wrap)


# ------------------------------------------------------------------ key/value
class KVWidget(QWidget):
    """Compact key-value rows for detail panels."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(6)

    def set_items(self, items: list[tuple[str, str]], mono_keys: tuple[str, ...] = ()) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for k, v in items:
            row = QWidget()
            row.setMinimumHeight(24)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(10)
            kl = label(k, "Muted", wordwrap=False)
            vl = label(v if v else "—", "", wordwrap=False)
            vl.setStyleSheet("font-size: 12.5px; font-weight: 600;")
            if k in mono_keys:
                vl.setStyleSheet(
                    "font-family: 'DejaVu Sans Mono', monospace; font-size: 12px; font-weight: 700;"
                )
            metrics = vl.fontMetrics()
            elided = metrics.elidedText(vl.text(), Qt.TextElideMode.ElideRight, 340)
            vl.setText(elided)
            vl.setToolTip(str(v))
            rl.addWidget(kl)
            rl.addStretch(1)
            rl.addWidget(vl, 2)
            self._lay.addWidget(row)
        self._lay.addStretch(1)


# --------------------------------------------------------------------- misc
def form_row(text: str, widget: QWidget) -> QWidget:
    row = QWidget()
    lay = QHBoxLayout(row)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(10)
    lbl = label(text, "H3", wordwrap=False)
    lbl.setFixedWidth(170)
    lay.addWidget(lbl)
    lay.addWidget(widget, 1)
    return row


def relative_time(iso_str: str) -> str:
    dt = None
    try:
        from ...database.repository import parse_iso

        dt = parse_iso(iso_str)
    except Exception:  # noqa: BLE001
        pass
    if not dt:
        return str(iso_str or "—")
    delta = (_now_utc() - dt).total_seconds()
    if delta < 90:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)} min ago"
    if delta < 86400:
        return f"{int(delta // 3600)} h ago"
    return f"{int(delta // 86400)} d ago"
