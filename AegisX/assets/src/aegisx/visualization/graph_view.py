"""
AegisX — threat relationship graph.

Self-contained force-directed graph renderer (spring-electrical model) on a
custom painted widget: smooth physics, draggable nodes, wheel zoom, pan,
severity-coloured nodes and evidence-labelled edges. Handles up to ~120
nodes comfortably at 30 fps.
"""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget

from ..styles import theme

EDGE_KIND_COLORS = {
    "same-asn": "#3B82F6",
    "resolves-to": "#16A34A",
    "campaign": "#DC2626",
    "shared-tags": "#F59E0B",
    "co-investigation": "#8B5CF6",
}


class GraphView(QWidget):
    """Interactive force-directed indicator relationship graph."""

    node_selected = Signal(dict)          # node payload dict
    edge_selected = Signal(dict)          # edge payload dict
    empty_click = Signal()

    REPULSION = 5200.0
    SPRING_LENGTH = 95.0
    SPRING_K = 0.045
    DAMPING = 0.82
    CENTER_PULL = 0.0015

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(420, 320)
        self.setMouseTracking(True)
        self.nodes: list[dict] = []
        self.edges: list[dict] = []
        self._selected = None            # ("node"|"edge", id)
        self._drag: dict | None = None
        self._panning = False
        self._pan_start = QPointF()
        self._offset = QPointF(0, 0)
        self._zoom = 1.0
        self._running = False

        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._physics)

    # ------------------------------------------------------------ public API
    def set_graph(self, nodes: list[dict], edges: list[dict]) -> None:
        """nodes: [{id,value,type,severity,...}] edges: [{source,target,kind,...}]"""
        self.nodes = []
        ids = {n["id"] for n in nodes}
        n = max(1, len(nodes))
        for i, node in enumerate(nodes):
            angle = 2 * math.pi * i / n
            self.nodes.append({
                "id": node["id"],
                "payload": node,
                "x": math.cos(angle) * (60 + 12 * (i % 7)),
                "y": math.sin(angle) * (60 + 12 * (i % 5)),
                "vx": 0.0, "vy": 0.0,
            })
        self.edges = []
        for e in edges:
            if e.get("source") in ids and e.get("target") in ids:
                self.edges.append(e)
        self._selected = None
        self._running = True
        self._timer.start()
        self.update()

    def clear(self) -> None:
        self.nodes = []
        self.edges = []
        self._timer.stop()
        self.update()

    def stop(self) -> None:
        self._timer.stop()
        self._running = False

    # -------------------------------------------------------------- physics
    def _physics(self) -> None:
        nodes = self.nodes
        total_energy = 0.0
        for i, a in enumerate(nodes):
            fx, fy = 0.0, 0.0
            for j, b in enumerate(nodes):
                if i == j:
                    continue
                dx, dy = a["x"] - b["x"], a["y"] - b["y"]
                d2 = dx * dx + dy * dy + 60.0
                f = self.REPULSION / d2
                d = math.sqrt(d2)
                fx += dx / d * f
                fy += dy / d * f
            # center gravity
            fx += -a["x"] * self.CENTER_PULL
            fy += -a["y"] * self.CENTER_PULL
            # springs
            for e in self.edges:
                if e["source"] == a["id"] or e["target"] == a["id"]:
                    other_id = e["target"] if e["source"] == a["id"] else e["source"]
                    other = next((n for n in nodes if n["id"] == other_id), None)
                    if other:
                        dx, dy = a["x"] - other["x"], a["y"] - other["y"]
                        d = math.sqrt(dx * dx + dy * dy) + 1e-6
                        f = self.SPRING_K * (d - self.SPRING_LENGTH)
                        fx -= dx / d * f
                        fy -= dy / d * f
            if self._drag and self._drag is a:
                continue
            a["vx"] = a["vx"] * self.DAMPING + fx
            a["vy"] = a["vy"] * self.DAMPING + fy
            a["x"] += max(-14, min(14, a["vx"]))
            a["y"] += max(-14, min(14, a["vy"]))
            total_energy += abs(a["vx"]) + abs(a["vy"])

        self.update()
        if total_energy < 3.5 and not self._drag:
            # settle: keep gentle idle pulse via timer only when selected
            self._timer.stop()

    def _wake(self) -> None:
        if not self._timer.isActive():
            self._timer.start()

    # ------------------------------------------------------------ transforms
    def _to_screen(self, x: float, y: float) -> QPointF:
        cx, cy = self.width() / 2 + self._offset.x(), self.height() / 2 + self._offset.y()
        return QPointF(cx + x * self._zoom, cy + y * self._zoom)

    def _from_screen(self, pos: QPointF) -> tuple[float, float]:
        cx, cy = self.width() / 2 + self._offset.x(), self.height() / 2 + self._offset.y()
        return (pos.x() - cx) / self._zoom, (pos.y() - cy) / self._zoom

    # -------------------------------------------------------------- painting
    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        if not self.nodes:
            painter.setPen(QPen(QColor(theme.COLORS["text_muted"])))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "Build a graph from an indicator to explore relationships.")
            return

        # edges
        for e in self.edges:
            a = next((n for n in self.nodes if n["id"] == e["source"]), None)
            b = next((n for n in self.nodes if n["id"] == e["target"]), None)
            if not a or not b:
                continue
            pa, pb = self._to_screen(a["x"], a["y"]), self._to_screen(b["x"], b["y"])
            color = QColor(EDGE_KIND_COLORS.get(e.get("kind", ""), theme.COLORS["graph_edge"]))
            selected = self._selected == ("edge", id(e))
            alpha = 235 if selected else 110
            c = QColor(color)
            c.setAlpha(alpha)
            pen = QPen(c, 2.4 if selected else 1.4)
            painter.setPen(pen)
            painter.drawLine(pa, pb)
            # label
            if selected or len(self.edges) <= 12:
                mid = QPointF((pa.x() + pb.x()) / 2, (pa.y() + pb.y()) / 2)
                painter.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
                f = painter.font()
                f.setPointSizeF(8.5)
                painter.setFont(f)
                painter.drawText(mid + QPointF(6, -4), e.get("kind", ""))

        # nodes
        for n in self.nodes:
            p = self._to_screen(n["x"], n["y"])
            payload = n["payload"]
            color = QColor(theme.SEVERITY_COLORS.get(payload.get("severity", "info"),
                                                     theme.COLORS["sev_info"]))
            selected = self._selected == ("node", id(n))
            radius = 9 if selected else 7.2

            painter.setPen(QPen(QColor("#FFFFFF"), 2))
            painter.setBrush(QBrush(color))
            painter.drawEllipse(p, radius, radius)

            label = str(payload.get("value", ""))[:26]
            painter.setPen(QPen(QColor(theme.COLORS["text"] if selected else theme.COLORS["text_secondary"])))
            f = painter.font()
            f.setPointSizeF(9 if selected else 8.5)
            painter.setFont(f)
            painter.drawText(QPointF(p.x() - radius, p.y() + radius + 13), label)

    # ---------------------------------------------------------- interaction
    def _node_at(self, pos: QPointF) -> dict | None:
        for n in reversed(self.nodes):
            p = self._to_screen(n["x"], n["y"])
            if (QPointF(p.x() - pos.x(), p.y() - pos.y())).manhattanLength() < 14:
                return n
        return None

    def mousePressEvent(self, event) -> None:  # noqa: N802
        pos = event.position()
        node = self._node_at(pos)
        if node:
            self._drag = node
            self._selected = ("node", id(node))
            self.node_selected.emit(node["payload"])
        else:
            self._panning = True
            self._pan_start = pos
        self._wake()
        self.update()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        pos = event.position()
        if self._drag:
            x, y = self._from_screen(pos)
            self._drag["x"], self._drag["y"] = x, y
            self._wake()
            self.update()
        elif self._panning:
            self._offset += pos - self._pan_start
            self._pan_start = pos
            self.update()

    def mouseReleaseEvent(self, _event) -> None:  # noqa: N802
        self._drag = None
        self._panning = False

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802
        node = self._node_at(event.position())
        if node:
            self.node_selected.emit(node["payload"])

    def wheelEvent(self, event) -> None:  # noqa: N802
        delta = event.angleDelta().y()
        factor = 1.12 if delta > 0 else 0.89
        self._zoom = max(0.35, min(3.2, self._zoom * factor))
        self.update()

    def hideEvent(self, event) -> None:  # noqa: N802
        self._timer.stop()
        super().hideEvent(event)
