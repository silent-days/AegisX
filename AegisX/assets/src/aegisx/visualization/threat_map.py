"""
AegisX — interactive global threat map.

Custom-painted, dot-matrix world map on a white card:
  * animated attack arcs between geo-located points
  * pulsing severity-coloured markers
  * click-to-select with a signal for detail panels
  * hover tooltips, legend, demo-mode watermark

No external tile service, no network requirement — fully offline.
"""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget

from ..styles import theme
from .mapdata import LAND_POLYGONS, WATER_OVERLAYS, is_land

PAD = 14


def project(lon: float, lat: float, rect: QRectF) -> QPointF:
    """Equirectangular projection into the map rect."""
    x = rect.left() + (lon + 180.0) / 360.0 * rect.width()
    y = rect.top() + (90.0 - lat) / 180.0 * rect.height()
    return QPointF(x, y)


class ThreatMapWidget(QWidget):
    """Interactive world threat map."""

    marker_selected = Signal(dict)       # plot point dict
    marker_hover = Signal(str)           # label or ""

    def __init__(self, parent=None, *, compact: bool = False) -> None:
        super().__init__(parent)
        self.compact = compact
        self.setMinimumSize(420, 260 if compact else 380)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self.points: list[dict] = []       # {value,label,lat,lon,severity,city,country}
        self.arcs: list[dict] = []         # {from:(lat,lon), to:(lat,lon), severity}
        self._selected_index = -1
        self._hover_index = -1
        self._phase = 0.0

        self._dots: list[QPointF] = []
        self._dot_rect = None
        self._water_paths: list[QPainterPath] = []
        self._land_paths: list[QPainterPath] = []

        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._tick)

        self._demo_mode = False

    # ------------------------------------------------------------ public API
    def set_plot_points(self, points: list[dict]) -> None:
        self.points = [p for p in points if p.get("lat") is not None]
        self._selected_index = -1
        self.update()

    def set_arcs(self, arcs: list[dict]) -> None:
        self.arcs = arcs
        self.update()

    def set_demo_mode(self, demo: bool) -> None:
        self._demo_mode = demo
        self.update()

    def start(self) -> None:
        if not self._timer.isActive():
            self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    # ------------------------------------------------------------- geometry
    def _map_rect(self) -> QRectF:
        w = self.width() - 2 * PAD
        h = self.height() - 2 * PAD
        target = w / 2.05                     # 2.05:1 aspect for the world
        if h <= target:
            rect_h = h
            rect_w = h * 2.05
        else:
            rect_w = w
            rect_h = w / 2.05
        return QRectF((self.width() - rect_w) / 2, (self.height() - rect_h) / 2 - 4,
                      rect_w, rect_h)

    def _ensure_dots(self) -> None:
        rect = self._map_rect()
        if self._dot_rect == rect and self._dots:
            return
        self._dot_rect = QRectF(rect)
        self._dots = []
        step_lon, step_lat = 2.4, 2.4
        lat = -60
        while lat <= 80:
            lon = -179
            while lon <= 179:
                if is_land(lon, lat):
                    self._dots.append(project(lon + step_lon / 2, lat + step_lat / 2, rect))
                lon += step_lon
            lat += step_lat

    # ------------------------------------------------------------------ anim
    def _tick(self) -> None:
        self._phase = (self._phase + 0.02) % 1.0
        self.update()

    # --------------------------------------------------------------- painting
    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = self._map_rect()
        self._ensure_dots()

        # land dots
        dot_color = QColor(theme.COLORS["land_dot"])
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(dot_color))
        r = 1.4 if self.compact else 1.7
        for pt in self._dots:
            painter.drawEllipse(pt, r, r)

        # graticule (very subtle)
        grid = QColor(theme.COLORS["graticule"])
        painter.setPen(QPen(grid, 1))
        for lon in range(-180, 181, 30):
            p1, p2 = project(lon, 90, rect), project(lon, -90, rect)
            painter.drawLine(p1, p2)
        for lat in range(-60, 81, 20):
            p1, p2 = project(-180, lat, rect), project(180, lat, rect)
            painter.drawLine(p1, p2)

        # arcs (attack flows)
        if not self.compact:
            self._paint_arcs(painter, rect)

        # markers
        self._paint_markers(painter, rect)

        # legend
        self._paint_legend(painter)

        # demo watermark
        if self._demo_mode:
            painter.setPen(QPen(QColor(theme.COLORS["warning"]), 1))
            f = painter.font()
            f.setBold(True)
            painter.setFont(f)
            painter.drawText(QRectF(8, self.height() - 26, 220, 20),
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             "DEMONSTRATION DATA")

    def _paint_arcs(self, painter: QPainter, rect: QRectF) -> None:
        for arc in self.arcs:
            color = QColor(theme.SEVERITY_COLORS.get(arc.get("severity", "medium"),
                                                     theme.COLORS["sev_medium"]))
            p1 = project(arc["from"][1], arc["from"][0], rect)
            p2 = project(arc["to"][1], arc["to"][0], rect)
            mid = QPointF((p1.x() + p2.x()) / 2, min(p1.y(), p2.y()) - abs(p1.x() - p2.x()) * 0.18 - 18)

            path = QPainterPath(p1)
            path.quadTo(mid, p2)

            pen = QPen(color)
            pen.setWidthF(1.6)
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([5, 6])
            pen.setDashOffset(12 * self._phase)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)

            # travelling comet head
            t = self._phase
            comet = path.pointAtPercent(t)
            grad = QRadialGradient(comet, 7)
            c = QColor(color)
            c.setAlpha(160)
            grad.setColorAt(0, c)
            c2 = QColor(color)
            c2.setAlpha(0)
            grad.setColorAt(1, c2)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(grad))
            painter.drawEllipse(comet, 7, 7)

    def _paint_markers(self, painter: QPainter, rect: QRectF) -> None:
        for i, pt in enumerate(self.points):
            pos = project(pt["lon"], pt["lat"], rect)
            color = QColor(theme.SEVERITY_COLORS.get(pt.get("severity", "medium"),
                                                     theme.COLORS["sev_medium"]))
            selected = i == self._selected_index
            pulse = (math.sin((self._phase * math.tau) + i) + 1) / 2

            # pulse ring
            ring = QColor(color)
            ring.setAlpha(int(90 * (1 - pulse)))
            painter.setPen(QPen(ring, 1.4))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            radius = 5 + pulse * (9 if selected else 6)
            painter.drawEllipse(pos, radius, radius)

            # core dot
            painter.setPen(QPen(QColor("#FFFFFF"), 1.4))
            painter.setBrush(QBrush(color))
            core = 6 if selected else 4.6
            painter.drawEllipse(pos, core, core)

    def _paint_legend(self, painter: QPainter) -> None:
        if self.compact:
            return
        painter.setPen(Qt.PenStyle.NoPen)
        x = 12
        y = self.height() - 30
        for sev, color in theme.SEVERITY_COLORS.items():
            painter.setBrush(QBrush(QColor(color)))
            painter.drawEllipse(QPointF(x, y), 5, 5)
            painter.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
            f = painter.font()
            f.setPointSizeF(9)
            painter.setFont(f)
            painter.drawText(QPointF(x + 10, y + 4), sev.capitalize())
            x += 10 + painter.fontMetrics().horizontalAdvance(sev.capitalize()) + 22

    # ------------------------------------------------------------- interaction
    def _nearest(self, pos: QPointF) -> int:
        rect = self._map_rect()
        best, best_d = -1, 18 ** 2
        for i, pt in enumerate(self.points):
            p = project(pt["lon"], pt["lat"], rect)
            d = (p.x() - pos.x()) ** 2 + (p.y() - pos.y()) ** 2
            if d < best_d:
                best, best_d = i, d
        return best

    def mousePressEvent(self, event) -> None:  # noqa: N802
        idx = self._nearest(event.position())
        self._selected_index = idx
        if idx >= 0:
            self.marker_selected.emit(self.points[idx])
        self.update()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        idx = self._nearest(event.position())
        if idx != self._hover_index:
            self._hover_index = idx
            if idx >= 0:
                pt = self.points[idx]
                self.marker_hover.emit(pt.get("label") or pt.get("value", ""))
                self.setToolTip(
                    f"{pt.get('value')}\n{pt.get('city') or ''} "
                    f"{pt.get('country') or ''}\nseverity: {pt.get('severity')}"
                )
            else:
                self.marker_hover.emit("")
                self.setToolTip("")
        super().mouseMoveEvent(event)

    def hideEvent(self, event) -> None:  # noqa: N802
        self.stop()
        super().hideEvent(event)

    def showEvent(self, event) -> None:  # noqa: N802
        self.start()
        super().showEvent(event)
