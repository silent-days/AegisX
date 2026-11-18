"""
AegisX — global threat network topology (dashboard hero centerpiece).

A custom-painted, animated radial network: the AegisX core sits at the
center, threat clusters (grouped by indicator type) orbit around it and
individual indicator nodes cluster around their hub. Severity pulses,
animated intel flows and hover/click inspection make the network feel
alive while remaining fully offline and data-driven.
"""

from __future__ import annotations

import math

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
from PySide6.QtWidgets import QWidget

from ...styles import theme
from ..logo import paint_shield

# cluster metadata: type key -> (display name, hub color)
HUB_META = [
    ("ip", "Malicious IPs", "#DC2626"),
    ("domain", "Phishing Domains", "#F97316"),
    ("url", "Malicious URLs", "#F59E0B"),
    ("hash", "File Hashes", "#8B5CF6"),
    ("asn", "ASN Infrastructure", "#3B82F6"),
]

_RING_COLORS = ["#DC2626", "#F97316", "#F59E0B", "#8B5CF6", "#3B82F6",
                "#16A34A", "#EF4444", "#FB7185"]


def _hex_rgb(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def _rgba(c: str, a: float) -> QColor:
    r, g, b = _hex_rgb(c)
    return QColor(r, g, b, max(0, min(255, int(a * 255))))


def _stable_jitter(value: str, salt: str = "") -> float:
    """Deterministic pseudo-random jitter in [-1, 1] from a string."""
    h = 2166136261
    for ch in salt + value:
        h = (h ^ ord(ch)) * 16777619 & 0xFFFFFFFF
    return ((h >> 8) & 0xFFFF) / 0x7FFF - 1.0


class ThreatTopologyWidget(QWidget):
    """Animated radial threat-intelligence network with hover inspection."""

    node_selected = Signal(dict)          # indicator payload on click

    MAX_PER_HUB = 12

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(360, 480)
        self.setMouseTracking(True)

        self._nodes: list[dict] = []
        self._hubs: list[dict] = []       # {type,name,color,angle,pos,ring}
        self._layout: list[dict] = []     # rendered nodes with pos/hub ref
        self._type_visible: dict[str, bool] = {}
        self._hover_value: str | None = None
        self._focus_value: str | None = None
        self._focus_until = 0
        self._zoom = 1.0
        self._tick = 0

        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(1200)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.valueChanged.connect(self._on_sweep)
        self._progress = 0.0

        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._on_tick)

    # ------------------------------------------------------------ public api
    def set_nodes(self, nodes: list[dict]) -> None:
        """Feed indicators: {value, type, severity, risk_score, ...}."""
        self._nodes = nodes
        self._recompute()
        self._anim.stop()
        self._anim.start()

    def set_type_visible(self, type_key: str, visible: bool) -> None:
        self._type_visible[type_key] = visible
        self._recompute()
        self.update()

    def visible_types(self) -> dict[str, bool]:
        return dict(self._type_visible)

    def zoom_in(self) -> None:
        self._zoom = min(1.7, self._zoom * 1.18)
        self._recompute()
        self.update()

    def zoom_out(self) -> None:
        self._zoom = max(0.62, self._zoom / 1.18)
        self._recompute()
        self.update()

    def reset_zoom(self) -> None:
        self._zoom = 1.0
        self._recompute()
        self.update()

    def focus_value(self, value: str) -> None:
        """Highlight a specific indicator (used by the overlay search)."""
        self._focus_value = value
        self._focus_until = self._tick + 150
        self.update()

    # ------------------------------------------------------------ internals
    def _on_sweep(self, v: float) -> None:
        self._progress = float(v)
        self.update()

    def _on_tick(self) -> None:
        self._tick += 1
        self.update()

    def showEvent(self, e) -> None:  # noqa: N802
        self._timer.start()
        super().showEvent(e)

    def hideEvent(self, e) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(e)

    def _recompute(self) -> None:
        w, h = max(self.width(), 10), max(self.height(), 10)
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 34
        hub_dist = radius * 0.54 * self._zoom
        node_dist = radius * 0.30 * self._zoom

        # group nodes by type
        groups: dict[str, list[dict]] = {}
        for n in self._nodes:
            t = n["type"] if n["type"] in ("domain", "url", "hash", "asn") else "ip"
            groups.setdefault(t, []).append(n)

        self._hubs = []
        used = []
        angle = -90.0
        present = [meta for meta in HUB_META if groups.get(meta[0])]
        step = 360.0 / max(1, len(present))
        for key, name, color in present:
            visible = self._type_visible.get(key, True)
            hub_angle = math.radians(angle)
            hx, hy = cx + hub_dist * math.cos(hub_angle), cy + hub_dist * math.sin(hub_angle)
            self._hubs.append({"type": key, "name": name, "color": color,
                               "angle": angle, "pos": QPointF(hx, hy),
                               "count": len(groups[key]), "visible": visible})
            if visible:
                for i, ind in enumerate(
                        sorted(groups[key], key=lambda n: -n.get("risk_score", 0))
                        [: self.MAX_PER_HUB]):
                    ring = 0.55 + 0.45 * ((i % 3) / 2)
                    spread = 148.0 / max(6, len(groups[key][:self.MAX_PER_HUB]))
                    a = angle + (i - (min(len(groups[key]), self.MAX_PER_HUB) - 1) / 2) * spread
                    a += _stable_jitter(ind["value"], "a") * 4.0
                    d = node_dist * ring * (1.0 + _stable_jitter(ind["value"], "r") * 0.08)
                    ar = math.radians(a)
                    px, py = hx + d * math.cos(ar), hy + d * math.sin(ar)
                    used.append({**ind, "pos": QPointF(px, py), "hub": color,
                                 "hub_type": key,
                                 "z": ring})   # pseudo-depth 0..1 (closer = bigger)
            angle += step
        self._layout = used

    # -------------------------------------------------------------- painting
    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        center = QPointF(cx, cy)
        radius = min(w, h) / 2 - 34
        pr = self._progress

        if not self._hubs:
            p.setPen(QPen(QColor(theme.COLORS["text_muted"])))
            f = QFont()
            f.setPointSizeF(10)
            p.setFont(f)
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                       "No indicators yet — run an investigation to populate\n"
                       "the global threat network.")
            return

        t = self._tick

        # ------- 3D perspective floor grid ---------------------------------
        # an elliptical ground plane under the network: concentric depth
        # rings + converging radial spokes give a holographic-projector feel
        floor_cy = cy + radius * 0.30
        floor_rx = radius * 1.05
        floor_ry = radius * 0.34
        floor_alpha = 26 + int(10 * math.sin(t / 120.0))
        for k in (1.0, 0.72, 0.46, 0.24):
            pen = QPen(_rgba("#9FB0C6", floor_alpha / 255 * (k + 0.35)), 1.1)
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.save()
            p.translate(cx, floor_cy)
            p.scale(1.0, floor_ry / max(1.0, floor_rx))
            p.drawEllipse(QPointF(0, 0), floor_rx * k, floor_rx * k)
            p.restore()
        for a_deg in range(0, 360, 30):
            ar = math.radians(a_deg)
            x0, y0 = cx + floor_rx * 0.10 * math.cos(ar), floor_cy + floor_ry * 0.10 * math.sin(ar)
            x1, y1 = cx + floor_rx * math.cos(ar), floor_cy + floor_ry * math.sin(ar)
            p.setPen(QPen(_rgba("#9FB0C6", floor_alpha / 255 * 0.8), 1.0))
            p.drawLine(QPointF(x0, y0), QPointF(x1, y1))

        # dashed radar rings (slow rotation)
        for rr, dash in ((radius * 0.86, 3), (radius * 0.60, 5)):
            pen = QPen(_rgba("#B7C4D6", 0.55), 1)
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([dash, 7])
            pen.setDashOffset(t * 0.12 * (1 if rr == radius * 0.60 else -1))
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(center, rr * self._zoom, rr * self._zoom)

        # soft radial wash behind the core
        wash = QRadialGradient(center, 120 * self._zoom)
        wash.setColorAt(0.0, _rgba(theme.COLORS["primary"], 0.10))
        wash.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(wash))
        p.drawEllipse(center, 130 * self._zoom, 130 * self._zoom)

        # edges center->hub + hub->node
        for hub in self._hubs:
            col = hub["color"]
            if hub["visible"]:
                grad = QLinearGradient(center, hub["pos"])
                grad.setColorAt(0.0, _rgba(col, 0.30))
                grad.setColorAt(1.0, _rgba(col, 0.75))
                p.setPen(QPen(QBrush(grad), 2.4, Qt.PenStyle.SolidLine,
                              Qt.PenCapStyle.RoundCap))
                p.drawLine(center, hub["pos"])
            elif hub["count"]:
                p.setPen(QPen(_rgba(col, 0.22), 1.6, Qt.PenStyle.DotLine))
                p.drawLine(center, hub["pos"])

            if hub["visible"]:
                for n in self._layout:
                    if n["hub_type"] == hub["type"]:
                        p.setPen(QPen(_rgba(col, 0.34), 1.1,
                                      Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                        p.drawLine(hub["pos"], n["pos"])

        # animated intel flows: hub -> core
        if pr >= 0.02:
            for hub in self._hubs:
                if not hub["visible"]:
                    continue
                col = hub["color"]
                for j in range(2):
                    phase = ((t / 210.0) + j * 0.5 + _stable_jitter(hub["type"], "f") * 0.2) % 1.0
                    ph = phase * min(1.0, pr)
                    pos = QPointF(
                        hub["pos"].x() + (center.x() - hub["pos"].x()) * ph,
                        hub["pos"].y() + (center.y() - hub["pos"].y()) * ph,
                    )
                    p.setPen(Qt.PenStyle.NoPen)
                    p.setBrush(_rgba(col, 0.85))
                    p.drawEllipse(pos, 3.0, 3.0)
                    p.setBrush(_rgba(col, 0.30))
                    p.drawEllipse(pos, 6.0, 6.0)

        # hub rings (with 3D pedestal shadow)
        f_hub = QFont()
        f_hub.setPointSizeF(8)
        f_hub.setBold(True)
        for hub in self._hubs:
            col, pos, c = hub["color"], hub["pos"], hub["count"]
            # pedestal shadow — raised-above-floor depth cue
            p.setPen(Qt.PenStyle.NoPen)
            ped = QRadialGradient(pos.x() + 5, pos.y() + 9, 24)
            ped.setColorAt(0.0, QColor(23, 31, 46, 52))
            ped.setColorAt(0.75, QColor(23, 31, 46, 16))
            ped.setColorAt(1.0, QColor(23, 31, 46, 0))
            p.setBrush(QBrush(ped))
            p.drawEllipse(QPointF(pos.x() + 5, pos.y() + 9), 22, 13)
            p.setBrush(QColor("#FFFFFF"))
            p.drawEllipse(pos, 15, 15)
            pen = QPen(_rgba(col, 1.0), 3.4)
            p.setPen(pen)
            p.setBrush(QColor("#FFFFFF"))
            p.drawEllipse(pos, 12, 12)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(_rgba(col, 0.28))
            p.drawEllipse(pos, 19, 19)
            # specular dot on hub (3D bead look)
            p.setBrush(QColor(255, 255, 255, 150))
            p.drawEllipse(QPointF(pos.x() - 4.5, pos.y() - 4.5), 2.6, 2.6)
            if c:
                p.setPen(QPen(_rgba(theme.COLORS["text_secondary"], 0.9)))
                p.setFont(f_hub)
                shown = int(round(c * pr)) if pr < 1 else c
                p.drawText(QRectF(pos.x() - 24, pos.y() + 20, 48, 16),
                           Qt.AlignmentFlag.AlignCenter, str(shown))

        # nodes (pseudo-3D: depth-scaled size, alpha and ground shadow)
        f = QFont()
        f.setPointSizeF(7)
        for i, n in enumerate(self._layout):
            sev = n.get("severity", "info")
            col = theme.SEVERITY_COLORS.get(sev, theme.SEVERITY_COLORS["info"])
            z = n.get("z", 0.6)
            pos = n["pos"]
            r = 4.2 + 3.0 * z
            appear = min(1.0, max(0.0, pr * 1.6 - (i % 12) * 0.045))
            if appear <= 0:
                continue
            # ground shadow under the node (depth)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(23, 31, 46, int(30 * appear * z)))
            p.drawEllipse(QPointF(pos.x() + 2.5, pos.y() + 3.5), r * 0.9, r * 0.55)
            # pulse for critical / high
            if sev in ("critical", "high"):
                ph = ((t / 90.0) + i * 0.13) % 1.0
                pr_r = r + 3 + 7 * ph
                pen = QPen(_rgba(col, 0.55 * (1 - ph)), 1.6)
                p.setPen(pen)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.drawEllipse(pos, pr_r, pr_r)
            glow = QRadialGradient(pos, r * 2.6)
            glow.setColorAt(0.0, _rgba(col, 0.35 * appear))
            glow.setColorAt(1.0, _rgba(col, 0.0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(glow))
            p.drawEllipse(pos, r * 2.6, r * 2.6)
            p.setBrush(_rgba(col, appear))
            p.setPen(QPen(QColor("#FFFFFF"), 1.8))
            p.drawEllipse(pos, r, r)
            # specular highlight (3D sphere look)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(255, 255, 255, int(120 * appear)))
            p.drawEllipse(QPointF(pos.x() - r * 0.34, pos.y() - r * 0.38),
                          r * 0.30, r * 0.30)

        # focus highlight
        if self._focus_value:
            for n in self._layout:
                if n["value"] == self._focus_value:
                    ph = (self._tick / 24.0) % 1.0
                    rr = 12 + 8 * ph
                    pen = QPen(_rgba("#DC2626", 0.8 * (1 - ph)), 2.4)
                    p.setPen(pen)
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.drawEllipse(n["pos"], rr, rr)

        # hover ring
        if self._hover_value:
            for n in self._layout:
                if n["value"] == self._hover_value:
                    p.setPen(QPen(_rgba(theme.COLORS["primary"], 0.9), 2.0))
                    p.setBrush(QColor(255, 255, 255, 40))
                    p.drawEllipse(n["pos"], 11.5, 11.5)

        # ------- the core: gradient ring + shield --------------------------
        core_r = 44 * self._zoom
        pulse = 0.5 + 0.5 * math.sin(t / 40.0)
        glow = QRadialGradient(center, core_r * 1.9)
        glow.setColorAt(0.0, _rgba("#DC2626", 0.22 + 0.10 * pulse))
        glow.setColorAt(0.72, _rgba("#EF4444", 0.06))
        glow.setColorAt(1.0, _rgba("#EF4444", 0.0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(glow))
        p.drawEllipse(center, core_r * 1.9, core_r * 1.9)

        seg_span = 360.0 / len(_RING_COLORS)
        pen = QPen()
        pen.setWidthF(9)
        pen.setCapStyle(Qt.PenCapStyle.FlatCap)
        for i, colr in enumerate(_RING_COLORS):
            pen.setColor(_rgba(colr, 0.95))
            p.setPen(pen)
            p.setBrush(Qt.BrushStyle.NoBrush)
            a0 = (t * 0.25 + i * seg_span) * 16
            rect = QRectF(center.x() - core_r, center.y() - core_r,
                          core_r * 2, core_r * 2)
            p.drawArc(rect, int(-a0 - seg_span * 16), int(seg_span * 16))

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#FFFFFF"))
        p.drawEllipse(center, core_r - 7, core_r - 7)
        shield_rect = QRectF(center.x() - 20 * self._zoom,
                             center.y() - 22 * self._zoom,
                             40 * self._zoom, 44 * self._zoom)
        paint_shield(p, shield_rect, size=40 * self._zoom)

    # ------------------------------------------------------- interaction
    def _node_at(self, pos: QPointF) -> dict | None:
        best, best_d = None, 15.5
        for n in self._layout:
            d = math.hypot(n["pos"].x() - pos.x(), n["pos"].y() - pos.y())
            if d < best_d:
                best, best_d = n, d
        return best

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        n = self._node_at(e.position())
        value = n["value"] if n else None
        if value != self._hover_value:
            self._hover_value = value
            self.setCursor(Qt.CursorShape.PointingHandCursor if n
                           else Qt.CursorShape.ArrowCursor)
            self.update()
        from PySide6.QtWidgets import QToolTip
        if n:
            tip = (f"{n['value']}\nRisk {n.get('risk_score', 0)}/100 · "
                   f"{str(n.get('severity', 'info')).upper()}")
            QToolTip.showText(e.globalPosition().toPoint(), tip, self)
        else:
            QToolTip.hideText()
        super().mouseMoveEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        if self._hover_value:
            self._hover_value = None
            self.update()
        super().leaveEvent(e)

    def mouseReleaseEvent(self, e) -> None:  # noqa: N802
        n = self._node_at(e.position())
        if n:
            self.node_selected.emit({k: v for k, v in n.items()
                                     if k not in ("pos", "hub", "hub_type")})
        super().mouseReleaseEvent(e)
