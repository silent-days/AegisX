"""
AegisX — custom painted chart widgets: animated donut, risk gauge and
mini sparkline. These complement the PyQtGraph charts with branded,
animated visualizations.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPointF, QRectF, Qt, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ...styles import theme


class _SweepAnimation(QVariantAnimation):
    """Reusable 0..1 sweep animation driven by QVariantAnimation."""

    def __init__(self, widget, duration=1100):
        super().__init__(widget)
        self._target = widget
        self.setStartValue(0.0)
        self.setEndValue(1.0)
        self.setDuration(duration)
        self.setEasingCurve(QEasingCurve.Type.OutCubic)


class DonutWidget(QWidget):
    """Animated severity distribution donut with legend."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(200, 190)
        self._segments: list[tuple[str, int, str]] = []
        self._progress = 0.0
        self._anim = _SweepAnimation(self, 1100)
        self._anim.valueChanged.connect(self._on_anim)
        self._hover_index = -1
        self.setMouseTracking(True)

    def _on_anim(self, v: float) -> None:
        self._progress = float(v)
        self.update()

    def set_data(self, data: dict[str, int]) -> None:
        total = sum(data.values()) or 1
        self._segments = [
            (sev, count, theme.SEVERITY_COLORS.get(sev, theme.COLORS["sev_info"]))
            for sev, count in sorted(
                data.items(), key=lambda kv: -kv[1]
            )
            if count > 0
        ]
        self._total = total
        self._anim.stop()
        self._anim.start()
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width() - 8, self.height() - 8)
        cx = 6 + side / 2 if not self._segments else self.width() * 0.34
        cy = self.height() / 2
        outer = min(side / 2, self.height() / 2 - 6)
        inner = outer * 0.62

        total = sum(c for _, c, _ in self._segments) or 1
        start = -90 * 16 * 1  # top
        shown = self._progress

        rect = QRectF(cx - outer, cy - outer, outer * 2, outer * 2)
        rect_in = QRectF(cx - inner, cy - inner, inner * 2, inner * 2)

        if not self._segments:
            p.setPen(QPen(QColor(theme.COLORS["text_muted"])))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No data yet")
            return

        sweep_total = 360 * 16 * shown
        acc = 0.0
        for name, count, color in self._segments:
            frac = count / total
            span = sweep_total * frac
            pen = QPen(QColor(color))
            pen.setWidthF(0)  # use brush fill
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            # draw arc band via path
            path_span = span / 16.0
            painter_span_deg = max(0.001, frac * 360 * shown)
            p.drawPie(rect, int(start + acc * 16), int(painter_span_deg * 16))
            acc += painter_span_deg

        # hole
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#FFFFFF"))
        p.drawEllipse(rect_in)

        # center text
        p.setPen(QPen(QColor(theme.COLORS["text"])))
        f = QFont()
        f.setPointSizeF(17)
        f.setBold(True)
        p.setFont(f)
        p.drawText(rect_in, Qt.AlignmentFlag.AlignCenter,
                   f"{int(round(total * min(1.0, shown)))}")

        # legend
        lx = cx + outer + 18
        ly = cy - len(self._segments) * 11
        f2 = QFont()
        f2.setPointSizeF(9)
        p.setFont(f2)
        for name, count, color in self._segments:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawEllipse(QPointF(lx + 5, ly + 6), 4.5, 4.5)
            p.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
            pct = f"{(count / total) * 100:.0f}%"
            p.drawText(QRectF(lx + 16, ly - 4, self.width() - lx - 10, 18),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       f"{name.capitalize()}  {count}  ({pct})")
            ly += 19


class GaugeWidget(QWidget):
    """Animated 0-100 risk gauge with severity arc and verdict."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(190, 148)
        self._value = 0
        self._target = 0
        self._label = "—"
        self._color = theme.SEVERITY_COLORS["info"]
        self._anim = _SweepAnimation(self, 1200)
        self._anim.valueChanged.connect(self._on_anim)

    def _on_anim(self, v: float) -> None:
        self._value = int(round(float(v) * 100))
        self.update()

    def set_score(self, score: int, severity: str, verdict: str = "") -> None:
        self._target = max(0, min(100, score))
        self._color = theme.SEVERITY_COLORS.get(severity, theme.SEVERITY_COLORS["info"])
        self._label = severity.upper()
        self._verdict = verdict or ""
        self._anim.stop()
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(self._target / 100.0)
        self._anim.start()
        self._value = 0
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        arc_h = h - 44
        side = min(w - 30, arc_h * 1.12)
        rect = QRectF((w - side) / 2, 12, side, side * 0.72)

        span = 240 * 16
        start = 150 * 16
        pen = QPen(QColor(theme.COLORS["divider"]), 11, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, start, -span)
        pen.setColor(QColor(self._color))
        p.setPen(pen)
        p.drawArc(rect, start, -int(span * self._value / 100))

        f = QFont()
        f.setPointSizeF(20)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QPen(QColor(self._color)))
        p.drawText(rect.adjusted(0, 6, 0, 6), Qt.AlignmentFlag.AlignCenter, f"{self._value}")

        # band label under the arc
        f2 = QFont()
        f2.setPointSizeF(9)
        f2.setBold(True)
        f2.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.4)
        p.setFont(f2)
        p.setPen(QPen(QColor(self._color)))
        band = QRectF(0, rect.bottom() + 4, w, 16)
        p.drawText(band, Qt.AlignmentFlag.AlignCenter, self._label)

        # verdict caption at the very bottom
        f3 = QFont()
        f3.setPointSizeF(8.5)
        p.setFont(f3)
        p.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
        p.drawText(QRectF(8, rect.bottom() + 20, w - 16, 16),
                   Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                   self._verdict if hasattr(self, "_verdict") else "")
