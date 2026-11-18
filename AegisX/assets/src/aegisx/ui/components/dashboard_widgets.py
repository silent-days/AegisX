"""
AegisX — premium dashboard support widgets.

Alert ticker, severity segment bar, animated mini bar chart, rotating
stat carousel, time-range chips and the interactive top-indicator panel.
All painted with Qt only — no external chart dependencies.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPointF,
    QRectF,
    Qt,
    QTimer,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ..icons import icon
from .widgets import GhostButton, label

MONO = "font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace; font-size: 12px; font-weight: 700;"


# ------------------------------------------------------------------ ticker
class AlertTicker(QFrame):
    """Auto-scrolling alert strip with severity chips; pauses on hover.

    Chips are positioned manually inside a fixed-size strip so the marquee
    can overflow its viewport without ever forcing the page wider.
    """

    see_all = Signal()

    STRIP_H = 34

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("TickerCard")
        self.setFixedHeight(46)

        root = QHBoxLayout(self)
        root.setContentsMargins(12, 6, 10, 6)
        root.setSpacing(10)

        bell = QLabel()
        bell.setPixmap(icon("bell", theme.COLORS["critical"], 17).pixmap(17, 17))
        bell.setStyleSheet("background: transparent;")
        root.addWidget(bell)

        self._host = QScrollArea()
        self._host.setWidgetResizable(False)
        self._host.setFrameShape(QFrame.Shape.NoFrame)
        self._host.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._host.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._host.setStyleSheet("background: transparent;")
        self._strip = QWidget()
        self._strip.setStyleSheet("background: transparent;")
        self._strip.setFixedHeight(self.STRIP_H)
        self._host.setWidget(self._strip)
        root.addWidget(self._host, 1)

        self._see = QLabel("See All")
        self._see.setStyleSheet(
            f"color: {theme.COLORS['primary']}; font-size: 11.5px; font-weight: 800;"
            "background: transparent;")
        self._see.setCursor(Qt.CursorShape.PointingHandCursor)
        self._see.mousePressEvent = lambda _e: self.see_all.emit()
        root.addWidget(self._see)

        self._chips: list[QWidget] = []
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setInterval(28)
        self._scroll_timer.timeout.connect(self._scroll_step)

    def _scroll_step(self) -> None:
        bar = self._host.horizontalScrollBar()
        if bar.maximum() <= 2:
            bar.setValue(0)
            return
        nxt = bar.value() + 1
        if nxt >= bar.maximum():
            nxt = 0
        bar.setValue(nxt)

    def _make_chip(self, alert: dict) -> QWidget:
        colors = {"critical": (theme.COLORS["critical"], "CRITICAL"),
                  "major": (theme.COLORS["warning"], "MAJOR"),
                  "minor": (theme.COLORS["info"], "INFO")}
        col, name = colors.get(alert.get("level", "minor"), colors["minor"])
        chip = QWidget()
        chip.setStyleSheet("background: transparent;")
        cl = QHBoxLayout(chip)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(7)
        pill = QFrame()
        pill.setStyleSheet(
            f"background: {theme.rgba_hex(col, 0.10)}; border-radius: 10px;")
        pl = QHBoxLayout(pill)
        pl.setContentsMargins(8, 2, 9, 2)
        pl.setSpacing(5)
        pd = QLabel()
        pd.setFixedSize(7, 7)
        pd.setStyleSheet(f"background: {col}; border-radius: 4px;")
        pl.addWidget(pd)
        pt = QLabel(name)
        pt.setStyleSheet(
            f"color: {col}; font-size: 10px; font-weight: 900; background: transparent;")
        pl.addWidget(pt)
        pill.setFixedHeight(21)
        cl.addWidget(pill)
        txt = QLabel(alert.get("text", ""))
        txt.setStyleSheet(
            "color: #374151; font-size: 12px; font-weight: 600; background: transparent;")
        txt.setWordWrap(False)
        cl.addWidget(txt)
        arrow = QLabel()
        arrow.setPixmap(icon("chevron-right", "#B9C2CF", 12).pixmap(12, 12))
        arrow.setStyleSheet("background: transparent;")
        cl.addWidget(arrow)
        chip.setFixedHeight(self.STRIP_H)
        return chip

    def set_alerts(self, alerts: list[dict]) -> None:
        for w in self._chips:
            w.deleteLater()
        self._chips = []
        self._see.setText(f"See All ({len(alerts)})")
        if not alerts:
            alerts = [{"level": "minor", "text": "No intelligence alerts yet"}]
        x = 0
        for a in alerts:
            chip = self._make_chip(a)
            chip.setParent(self._strip)
            chip.ensurePolished()
            w = max(48, chip.sizeHint().width())
            chip.setGeometry(x, 0, w, self.STRIP_H)
            chip.show()
            self._chips.append(chip)
            x += w + 14
        self._strip.setFixedWidth(max(1, x))
        self._host.horizontalScrollBar().setValue(0)
        # give the initial view a clean, readable moment before the marquee starts
        QTimer.singleShot(4000, self._scroll_timer.start)

    def enterEvent(self, e) -> None:  # noqa: N802
        self._scroll_timer.stop()
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        self._scroll_timer.start()
        super().leaveEvent(e)


# ------------------------------------------------------ range chips
class RangeChips(QFrame):
    """Segmented time-range selector (Last 24 Hours / 7 Days / 30 Days)."""

    range_changed = Signal(int)

    RANGES = [(1, "Last 24 Hours"), (7, "Last 7 Days"), (30, "Last 30 Days")]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("RangeChips")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 3, 4, 3)
        lay.setSpacing(2)
        self._buttons: list[QPushButton] = []
        for days, text in self.RANGES:
            b = QPushButton(text)
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setStyleSheet(self._style(False))
            b.clicked.connect(lambda _c=False, d=days: self._pick(d))
            lay.addWidget(b)
            self._buttons.append(b)
        self._buttons[1].setChecked(True)
        self._buttons[1].setStyleSheet(self._style(True))
        self._days = 7

    @staticmethod
    def _style(active: bool) -> str:
        if active:
            return ("QPushButton { background: #DC2626; color: white; border: 0;"
                    "border-radius: 8px; padding: 5px 12px; font-size: 11.5px;"
                    "font-weight: 800; }")
        return ("QPushButton { background: transparent; color: #64748B; border: 0;"
                "border-radius: 8px; padding: 5px 12px; font-size: 11.5px;"
                "font-weight: 700; }"
                "QPushButton:hover { background: #F1F5F9; color: #DC2626; }")

    def _pick(self, days: int) -> None:
        if days == self._days:
            return
        self._days = days
        for b, (d, _t) in zip(self._buttons, self.RANGES):
            b.setChecked(d == days)
            b.setStyleSheet(self._style(d == days))
        self.range_changed.emit(days)

    def days(self) -> int:
        return self._days



# ------------------------------------------------------ segment bar
class SegmentBar(QWidget):
    """Rounded severity segments with gaps (network-status style)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(12)
        self._segments: list[tuple[str, int, str]] = []

    def set_segments(self, segments: list[tuple[str, int, str]]) -> None:
        self._segments = segments
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        total = sum(c for _, c, _ in self._segments) or 1
        gap = 3.0
        avail = self.width() - gap * max(0, len(self._segments) - 1)
        x = 0.0
        for _name, count, color in self._segments:
            w = max(4.0, avail * (count / total))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawRoundedRect(QRectF(x, 0.5, w, self.height() - 1), 5, 5)
            x += w + gap


# ------------------------------------------------------ 3D metric gauge
class MetricGauge(QWidget):
    """Premium 3D-style radial gauge: gradient ring, gloss highlight,
    inset dial face and an animated count-up readout.

    Painted entirely with Qt — depth cues (drop shadow under the ring,
    bottom-weighted inner shading and a specular arc) give the illusion
    of a raised physical dial without any 3D engine.
    """

    def __init__(self, title: str, accent: str, *, unit: str = "%",
                 caption: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._title = title
        self._accent = accent
        self._unit = unit
        self._caption = caption
        self._fraction = 0.0          # 0..1
        self._display = 0.0           # animated readout 0..100
        self._glow = 0.0              # intro sweep 0..1
        self.setMinimumSize(150, 148)
        self._anim = QVariantAnimation(self)
        self._anim.setDuration(950)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_anim)

    def _on_anim(self, v: float) -> None:
        self._display = float(v)
        self.update()

    def set_fraction(self, frac: float, caption: str | None = None) -> None:
        """Set gauge fill (0..1) and optionally the caption text."""
        self._fraction = max(0.0, min(1.0, float(frac)))
        if caption is not None:
            self._caption = caption
        self._glow = 0.0
        self._anim.stop()
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(self._fraction * 100.0)
        self._anim.start()

    def _ring_rect(self) -> QRectF:
        side = min(self.width(), self.height() - 34)
        side = max(60.0, side)
        cx = self.width() / 2
        top = 6.0
        return QRectF(cx - side / 2, top, side, side)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        ring = self._ring_rect()
        cx, cy = ring.center().x(), ring.center().y()
        lw = max(9.0, ring.width() * 0.115)
        frac = min(1.0, self._display / 100.0) if self._display else 0.0
        inset = lw / 2 + 2

        # soft drop shadow under the whole dial (depth)
        sh = QRectF(ring.adjusted(3, 6, 3, 6))
        grad_sh = QRadialGradient(sh.center(), sh.width() / 2)
        grad_sh.setColorAt(0.62, QColor(23, 31, 46, 34))
        grad_sh.setColorAt(0.95, QColor(23, 31, 46, 6))
        grad_sh.setColorAt(1.0, QColor(23, 31, 46, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(grad_sh))
        p.drawEllipse(sh)

        # track (recessed groove)
        p.setPen(QPen(QColor("#E8EDF3"), lw, Qt.PenStyle.SolidLine,
                      Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(ring.adjusted(inset, inset, -inset, -inset), 0, 360 * 16)

        # value arc — gradient ring
        span = int(-360 * 16 * frac)
        arc = ring.adjusted(inset, inset, -inset, -inset)
        ring_grad = QLinearGradient(ring.topLeft(), ring.bottomRight())
        ring_grad.setColorAt(0.0, QColor(self._accent))
        ring_grad.setColorAt(1.0, QColor("#EF4444")
                             if self._accent == "#DC2626"
                             else QColor(self._accent).lighter(130).name())
        pen = QPen(QBrush(ring_grad), lw, Qt.PenStyle.SolidLine,
                   Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(arc, 90 * 16, span)

        # specular highlight (gloss) on the upper-left of the ring
        p.setPen(QPen(QColor(255, 255, 255, 130), lw * 0.34,
                      Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(arc, 118 * 16, 46 * 16)

        # dial face: white with bottom shading (inset look)
        face = ring.adjusted(lw * 1.15, lw * 1.15, -lw * 1.15, -lw * 1.15)
        face_grad = QRadialGradient(cx, face.center().y() - face.height() * 0.18,
                                    face.width() * 0.75)
        face_grad.setColorAt(0.0, QColor("#FFFFFF"))
        face_grad.setColorAt(0.8, QColor("#FDFEFE"))
        face_grad.setColorAt(1.0, QColor("#E9EEF4"))
        p.setPen(QPen(QColor("#DDE4EC"), 1))
        p.setBrush(QBrush(face_grad))
        p.drawEllipse(face)

        # readout
        f_val = QFont()
        f_val.setPointSizeF(max(12.0, face.width() * 0.135))
        f_val.setBold(True)
        p.setFont(f_val)
        p.setPen(QPen(QColor("#111827")))
        shown = int(round(self._display))
        p.drawText(QRectF(face.x(), face.y() + face.height() * 0.16,
                          face.width(), face.height() * 0.44),
                   Qt.AlignmentFlag.AlignCenter, f"{shown}{self._unit}")

        # caption inside the dial
        f_cap = QFont()
        f_cap.setPointSizeF(max(6.5, face.width() * 0.062))
        p.setFont(f_cap)
        p.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
        p.drawText(QRectF(face.x(), face.y() + face.height() * 0.60,
                          face.width(), face.height() * 0.24),
                   Qt.AlignmentFlag.AlignCenter, self._caption)

        # title below
        f_t = QFont()
        f_t.setPointSizeF(8.5)
        f_t.setBold(True)
        p.setFont(f_t)
        p.setPen(QPen(QColor("#334155")))
        p.drawText(QRectF(0, ring.bottom() + 8, self.width(), 18),
                   Qt.AlignmentFlag.AlignCenter, self._title.upper())


# ------------------------------------------------------ mini bars
class MiniBarChart(QWidget):
    """Animated pseudo-3D vertical bar chart with hover highlight.

    Each bar is drawn as an extruded prism: front face, darker right side
    face, lighter top face and a soft ground shadow — a convincing 3D
    look while staying fully hand-painted.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(120)
        self._data: list[tuple[str, float]] = []
        self._hover = -1
        self._progress = 0.0
        self.setMouseTracking(True)
        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(620)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_anim)

    def _on_anim(self, v: float) -> None:
        self._progress = float(v)
        self.update()

    def set_data(self, data: list[tuple[str, float]]) -> None:
        self._data = data
        self._anim.stop()
        self._anim.start()

    def _bar_rects(self) -> list[tuple[QRectF, int]]:
        rects = []
        n = len(self._data) or 1
        label_h = 18
        chart_h = self.height() - label_h - 6
        depth = 7.0
        gap = 10.0
        bw = (self.width() - gap * (n - 1) - depth) / n
        mx = max((v for _, v in self._data), default=1) or 1
        for i, (_name, val) in enumerate(self._data):
            h = max(3.0, chart_h * (val / mx) * self._progress)
            x = i * (bw + gap + depth)
            rects.append((QRectF(x, chart_h - h, bw, h), i))
        return rects

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        f = QFont()
        f.setPointSizeF(8)
        p.setFont(f)
        chart_h = self.height() - 24
        depth = 7.0
        for rect, i in self._bar_rects():
            name, val = self._data[i]
            hovered = i == self._hover
            front = QColor("#DC2626" if hovered else "#EF4444")
            front_bot = QColor("#F87171" if hovered else "#FCA5A5")
            side = QColor("#B91C1C" if hovered else "#DC8484")
            top = QColor("#F97373" if hovered else "#FDBABA")

            # ground shadow
            sh = QRectF(rect.x() + 3, chart_h + 1, rect.width() + depth, 5)
            grad_sh = QLinearGradient(sh.topLeft(), sh.bottomLeft())
            grad_sh.setColorAt(0.0, QColor(23, 31, 46, 40))
            grad_sh.setColorAt(1.0, QColor(23, 31, 46, 0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(grad_sh))
            p.drawRoundedRect(sh, 3, 3)

            # side face (right, darker — extrusion depth)
            p.setBrush(side)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawPolygon([QPointF(rect.right(), rect.top()),
                           QPointF(rect.right() + depth, rect.top() + depth * 0.6),
                           QPointF(rect.right() + depth, rect.bottom() + depth * 0.6),
                           QPointF(rect.right(), rect.bottom())])

            # top face (lighter — catches light)
            p.setBrush(top)
            p.drawPolygon([QPointF(rect.left(), rect.top()),
                           QPointF(rect.right(), rect.top()),
                           QPointF(rect.right() + depth, rect.top() + depth * 0.6),
                           QPointF(rect.left() + depth, rect.top() + depth * 0.6)])

            # front face with vertical gradient
            grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
            grad.setColorAt(0.0, front)
            grad.setColorAt(1.0, front_bot)
            p.setBrush(QBrush(grad))
            p.drawRoundedRect(rect, 4, 4)

            p.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
            elided = p.fontMetrics().elidedText(
                name, Qt.TextElideMode.ElideRight, int(rect.width() + 8))
            p.drawText(QRectF(rect.x() - 4, chart_h + 6, rect.width() + 8, 16),
                       Qt.AlignmentFlag.AlignCenter, elided)

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        idx = -1
        for rect, i in self._bar_rects():
            if rect.adjusted(-4, -8, 8, 20).contains(e.position()):
                idx = i
        if idx != self._hover:
            self._hover = idx
            self.update()
        if idx >= 0:
            from PySide6.QtWidgets import QToolTip
            name, val = self._data[idx]
            QToolTip.showText(e.globalPosition().toPoint(),
                              f"{name}: {int(val)} indicators", self)
        super().mouseMoveEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        self._hover = -1
        self.update()
        super().leaveEvent(e)


# ------------------------------------------------------ carousel
class CarouselCard(QWidget):
    """Rotating statistic slides with dots + prev/next arrows."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._slides: list[dict] = []
        self._index = 0
        self._fade = 1.0

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        self._body = QLabel("—")
        self._body.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._body.setWordWrap(True)
        self._body.setMinimumHeight(88)
        self._body.setMinimumWidth(1)
        self._body.setTextFormat(Qt.TextFormat.RichText)
        self._body.setStyleSheet("background: transparent;")
        lay.addWidget(self._body, 1)
        nav = QHBoxLayout()
        nav.setSpacing(6)
        self._dots_lay = QHBoxLayout()
        self._dots_lay.setSpacing(5)
        nav.addStretch(1)
        self._prev = GhostButton("", "chevron-left")
        self._prev.setFixedSize(30, 30)
        self._prev.clicked.connect(lambda: self._step(-1))
        nav.addWidget(self._prev)
        nav.addLayout(self._dots_lay)
        self._next = GhostButton("", "chevron-right")
        self._next.setFixedSize(30, 30)
        self._next.clicked.connect(lambda: self._step(1))
        nav.addWidget(self._next)
        nav.addStretch(1)
        lay.addLayout(nav)

        self._fade_anim = QVariantAnimation(self)
        self._fade_anim.setDuration(260)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self._fade_anim.valueChanged.connect(self._on_fade)

        self._timer = QTimer(self)
        self._timer.setInterval(6000)
        self._timer.timeout.connect(lambda: self._step(1))

    def _on_fade(self, v: float) -> None:
        self._fade = float(v)
        self._render_body()
        self.update()

    def set_slides(self, slides: list[dict]) -> None:
        self._slides = slides
        self._index = min(self._index, max(0, len(slides) - 1))
        self._rebuild_dots()
        self._render_body()
        self._timer.start()

    def _rebuild_dots(self) -> None:
        while self._dots_lay.count():
            item = self._dots_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for i in range(len(self._slides)):
            d = QLabel()
            d.setFixedSize(8, 8)
            on = i == self._index
            d.setStyleSheet(
                f"background: {theme.COLORS['primary'] if on else '#E2E8F0'};"
                "border-radius: 4px;")
            d.setCursor(Qt.CursorShape.PointingHandCursor)
            d.mousePressEvent = lambda _e, k=i: self._goto(k)
            self._dots_lay.addWidget(d)

    def _render_body(self) -> None:
        if not self._slides:
            self._body.setText("No intelligence statistics yet.")
            return
        s = self._slides[self._index]
        col = s.get("accent", theme.COLORS["primary"])
        html = (
            f"<div style='line-height:155%;'>"
            f"<span style='color:{col}; font-size:11px; font-weight:800;'>"
            f"{s['title']}</span><br>"
            f"<span style='color:#111827; font-size:23px; font-weight:900;'>"
            f"{s['value']}</span>"
            f"<span style='color:#16A34A; font-size:11.5px; font-weight:800;'>"
            f"&nbsp;&nbsp;{s.get('delta', '')}</span><br>"
            f"<span style='color:#64748B; font-size:11px;'>{s.get('caption', '')}</span>"
            f"</div>"
        )
        self._body.setText(html)
        effect = QGraphicsOpacityEffect(self._body)
        effect.setOpacity(self._fade)
        self._body.setGraphicsEffect(effect)

    def _goto(self, k: int) -> None:
        self._index = k
        self._rebuild_dots()
        self._animate_swap()

    def _step(self, d: int) -> None:
        if not self._slides:
            return
        self._index = (self._index + d) % len(self._slides)
        self._rebuild_dots()
        self._animate_swap()

    def _animate_swap(self) -> None:
        self._fade_anim.stop()
        self._fade_anim.setStartValue(0.25)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.start()


# -------------------------------------------------- top indicator panel
class TopIndicatorPanel(QWidget):
    """Tabbed list of top indicators with severity filter chips."""

    indicator_activated = Signal(dict)

    TABS = [("ip", "Network IPs"), ("domain", "Domains & URLs")]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows_all: dict[str, list[dict]] = {"ip": [], "domain": []}
        self._tab = "ip"
        self._filter = ""

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        tabs = QHBoxLayout()
        tabs.setSpacing(6)
        self._tab_btns = {}
        for key, text in self.TABS:
            b = QPushButton(text)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setCheckable(True)
            b.clicked.connect(lambda _c=False, k=key: self.set_tab(k))
            tabs.addWidget(b)
            self._tab_btns[key] = b
        tabs.addStretch(1)
        lay.addLayout(tabs)

        chips = QHBoxLayout()
        chips.setSpacing(4)
        self._chip_btns = {}
        for f in ("", "critical", "high", "medium"):
            c = QPushButton("All" if not f else f.capitalize())
            c.setCursor(Qt.CursorShape.PointingHandCursor)
            c.setCheckable(True)
            c.clicked.connect(lambda _c=False, k=f: self.set_filter(k))
            chips.addWidget(c)
            self._chip_btns[f] = c
        chips.addStretch(1)
        lay.addLayout(chips)

        self._list_host = QScrollArea()
        self._list_host.setWidgetResizable(True)
        self._list_host.setFrameShape(QFrame.Shape.NoFrame)
        self._list_host.setStyleSheet("background: transparent;")
        self._list = QWidget()
        self._list.setStyleSheet("background: transparent;")
        self._list_lay = QVBoxLayout(self._list)
        self._list_lay.setContentsMargins(0, 0, 0, 0)
        self._list_lay.setSpacing(2)
        self._list_host.setWidget(self._list)
        lay.addWidget(self._list_host, 1)

        self.set_filter("")
        self.set_tab("ip")

    def _style_tab(self, b, active: bool) -> None:
        if active:
            b.setStyleSheet(
                "QPushButton { background: #FEF2F2; color: #DC2626; border: 1px solid #FECACA;"
                "border-radius: 8px; padding: 5px 10px; font-size: 11px; font-weight: 800; }")
        else:
            b.setStyleSheet(
                "QPushButton { background: transparent; color: #64748B; border: 1px solid transparent;"
                "border-radius: 8px; padding: 5px 10px; font-size: 11px; font-weight: 700; }"
                "QPushButton:hover { color: #DC2626; background: #F8FAFC; }")

    def _style_chip(self, b, active: bool) -> None:
        if active:
            b.setStyleSheet(
                "QPushButton { background: #DC2626; color: white; border: 0;"
                "border-radius: 9px; padding: 2px 7px; font-size: 10px; font-weight: 800; }")
        else:
            b.setStyleSheet(
                "QPushButton { background: #F1F5F9; color: #64748B; border: 0;"
                "border-radius: 9px; padding: 2px 7px; font-size: 10px; font-weight: 700; }"
                "QPushButton:hover { background: #E2E8F0; }")

    def set_tab(self, key: str) -> None:
        self._tab = key
        for k, b in self._tab_btns.items():
            b.setChecked(k == key)
            self._style_tab(b, k == key)
        self._render()

    def set_filter(self, f: str) -> None:
        self._filter = f
        for k, b in self._chip_btns.items():
            b.setChecked(k == f)
            self._style_chip(b, k == f)
        self._render()

    def set_rows(self, ip_rows: list[dict], domain_rows: list[dict]) -> None:
        self._rows_all = {"ip": ip_rows, "domain": domain_rows}
        self._render()

    def _render(self) -> None:
        while self._list_lay.count():
            item = self._list_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        rows = [r for r in self._rows_all.get(self._tab, [])
                if not self._filter or r.get("severity") == self._filter][:9]
        if not rows:
            self._list_lay.addWidget(label(
                "No matching indicators for this window.", "Muted"))
            self._list_lay.addStretch(1)
            return
        sev_col = theme.SEVERITY_COLORS
        for r in rows:
            row = QFrame()
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            row.setStyleSheet(
                "QFrame { background: transparent; border-radius: 8px; padding: 3px 6px; }"
                f"QFrame:hover {{ background: {theme.COLORS['hover']}; }}")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(8, 5, 8, 5)
            rl.setSpacing(8)
            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(
                f"background: {sev_col.get(r.get('severity', 'info'), '#64748B')};"
                "border-radius: 4px;")
            rl.addWidget(dot)
            val = QLabel(str(r.get("value", "")))
            val.setStyleSheet(MONO + "color: #1F2937;")
            fm = val.fontMetrics()
            val.setText(fm.elidedText(val.text(), Qt.TextElideMode.ElideMiddle, 150))
            rl.addWidget(val, 1)
            risk = QLabel(f"{int(r.get('risk_score', 0))} Risk")
            risk.setStyleSheet(
                f"color: {sev_col.get(r.get('severity', 'info'), '#64748B')};"
                "font-size: 11px; font-weight: 800; background: transparent;")
            rl.addWidget(risk)
            rl.addWidget(label("", "Muted", wordwrap=False))
            row.mouseReleaseEvent = lambda e, d=dict(r): self.indicator_activated.emit(d)
            self._list_lay.addWidget(row)
        self._list_lay.addStretch(1)
