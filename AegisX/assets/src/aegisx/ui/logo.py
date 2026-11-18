"""
AegisX — brand mark painting (premium 3D edition).

Shared vector shield logo drawn with QPainter so every surface (splash,
sidebar, title bar, About, reports) renders the same crisp brand mark
without bitmap assets.

v1.2: layered 3D treatment — cast shadow, metallic bevel edge, gloss
sweep across the face, inset inner plate, gradient monogram and an
optional red "X" signature badge.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)

from ..styles import theme


def shield_path(r: QRectF) -> QPainterPath:
    """Aegis shield outline path within rect r."""
    path = QPainterPath()
    x, y = r.left(), r.top()
    w, h = r.width(), r.height()
    path.moveTo(x + w * 0.5, y)
    path.cubicTo(x + w * 0.72, y + h * 0.06, x + w * 0.88, y + h * 0.10,
                 x + w * 0.94, y + h * 0.10)
    path.lineTo(x + w * 0.94, y + h * 0.44)
    path.cubicTo(x + w * 0.94, y + h * 0.72, x + w * 0.70, y + h * 0.90,
                 x + w * 0.5, y + h)
    path.cubicTo(x + w * 0.30, y + h * 0.90, x + w * 0.06, y + h * 0.72,
                 x + w * 0.06, y + h * 0.44)
    path.lineTo(x + w * 0.06, y + h * 0.10)
    path.cubicTo(x + w * 0.12, y + h * 0.10, x + w * 0.28, y + h * 0.06,
                 x + w * 0.5, y)
    path.closeSubpath()
    return path


def paint_shield(painter: QPainter, rect: QRectF, *,
                 size: float | None = None, flat: bool = False,
                 badge_x: bool = False) -> None:
    """Draw the premium AegisX shield mark.

    ``badge_x=True`` renders the small red "X" signature badge at the
    lower-right corner (use on large placements: splash, About).
    """
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    s = size or min(rect.width(), rect.height())
    shield_rect = QRectF(rect.left() + (rect.width() - s * 0.82) / 2,
                         rect.top() + (rect.height() - s) / 2,
                         s * 0.82, s)

    path = shield_path(shield_rect)

    if flat:
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(theme.COLORS["primary"]))
        painter.drawPath(path)
        painter.restore()
        return

    # ---- cast shadow (depth: shield floats above the surface) -----------
    shadow_rect = shield_rect.translated(s * 0.02, s * 0.045)
    shadow_path = shield_path(shadow_rect)
    sh_grad = QRadialGradient(shadow_rect.center(), s * 0.62)
    sh_grad.setColorAt(0.42, QColor(23, 31, 46, 64))
    sh_grad.setColorAt(0.82, QColor(23, 31, 46, 18))
    sh_grad.setColorAt(1.0, QColor(23, 31, 46, 0))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(sh_grad)
    painter.drawPath(shadow_path)

    # ---- metallic bevel edge (outer ring) -------------------------------
    edge_rect = shield_rect.adjusted(-s * 0.012, -s * 0.012,
                                     s * 0.012, s * 0.012)
    edge_path = shield_path(edge_rect)
    edge_grad = QLinearGradient(edge_rect.topLeft(), edge_rect.bottomRight())
    edge_grad.setColorAt(0.0, QColor("#F8FAFC"))
    edge_grad.setColorAt(0.35, QColor("#CBD5E1"))
    edge_grad.setColorAt(0.55, QColor("#94A3B8"))
    edge_grad.setColorAt(0.75, QColor("#E2E8F0"))
    edge_grad.setColorAt(1.0, QColor("#B91C1C"))
    painter.setPen(QPen(QColor(255, 255, 255, 190), s * 0.008))
    painter.setBrush(edge_grad)
    painter.drawPath(edge_path)

    # ---- main red face ----------------------------------------------------
    grad = QLinearGradient(shield_rect.topLeft(), shield_rect.bottomRight())
    grad.setColorAt(0.0, QColor("#EF4444"))
    grad.setColorAt(0.55, QColor(theme.COLORS["primary"]))
    grad.setColorAt(1.0, QColor("#B91C1C"))
    painter.setPen(QPen(QColor("#FFFFFF"), s * 0.014))
    painter.setBrush(grad)
    painter.drawPath(path)

    # ---- gloss sweep (glass highlight across the top) --------------------
    # v1.0 fix: clip strictly to the shield outline so the highlight can
    # never leak outside the emblem corners (the old union-clip did).
    painter.setPen(Qt.PenStyle.NoPen)
    gloss = QLinearGradient(
        shield_rect.topLeft(),
        QPointF(shield_rect.left(),
                shield_rect.top() + shield_rect.height() * 0.52))
    gloss.setColorAt(0.0, QColor(255, 255, 255, 88))
    gloss.setColorAt(0.55, QColor(255, 255, 255, 26))
    gloss.setColorAt(1.0, QColor(255, 255, 255, 0))
    painter.setBrush(gloss)
    painter.save()
    painter.setClipPath(path)
    painter.drawRect(QRectF(shield_rect.left(), shield_rect.top(),
                            shield_rect.width(),
                            shield_rect.height() * 0.52))
    painter.restore()

    # ---- inner white plate (inset, bottom-shaded) -------------------------
    inner = shield_path(QRectF(shield_rect.left() + s * 0.075,
                               shield_rect.top() + s * 0.075,
                               shield_rect.width() - s * 0.15,
                               shield_rect.height() - s * 0.15))
    inner_grad = QLinearGradient(shield_rect.topLeft(), shield_rect.bottomLeft())
    inner_grad.setColorAt(0.0, QColor("#FFFFFF"))
    inner_grad.setColorAt(0.72, QColor("#F6F8FB"))
    inner_grad.setColorAt(1.0, QColor("#E4EAF1"))
    painter.setBrush(inner_grad)
    painter.setPen(QPen(QColor(255, 255, 255, 150), s * 0.012))
    painter.drawPath(inner)

    # ---- monogram "A" (gradient + soft shadow) ----------------------------
    f = QFont()
    f.setPointSizeF(max(6.0, s * 0.30))
    f.setBold(True)
    f.setKerning(False)
    painter.setFont(f)
    a_rect = QRectF(shield_rect.left(), shield_rect.top() + s * 0.03,
                    shield_rect.width(), shield_rect.height() * 0.78)
    painter.setPen(QPen(QColor(185, 28, 28, 70)))
    painter.drawText(a_rect.translated(s * 0.008, s * 0.010),
                     Qt.AlignmentFlag.AlignCenter |
                     Qt.AlignmentFlag.AlignVCenter, "A")
    a_grad = QLinearGradient(a_rect.topLeft(), a_rect.bottomLeft())
    a_grad.setColorAt(0.0, QColor("#DC2626"))
    a_grad.setColorAt(1.0, QColor("#7F1D1D"))
    painter.setPen(QPen(a_grad, 0))
    painter.drawText(a_rect,
                     Qt.AlignmentFlag.AlignCenter |
                     Qt.AlignmentFlag.AlignVCenter, "A")

    # ---- refined keyline --------------------------------------------------
    painter.setPen(QPen(QColor(255, 255, 255, 60), s * 0.014))
    painter.drawLine(QPointF(shield_rect.left() + s * 0.14,
                             shield_rect.top() + s * 0.345),
                     QPointF(shield_rect.right() - s * 0.14,
                             shield_rect.top() + s * 0.345))

    # ---- red "X" signature badge ------------------------------------------
    if badge_x and s >= 64:
        b_r = s * 0.135
        b_cx = shield_rect.right() - b_r * 0.55
        b_cy = shield_rect.top() + shield_rect.height() * 0.80
        # badge shadow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(23, 31, 46, 60))
        painter.drawEllipse(QPointF(b_cx + 1.5, b_cy + 2.5), b_r, b_r)
        # badge body
        b_grad = QLinearGradient(b_cx - b_r, b_cy - b_r,
                                 b_cx + b_r, b_cy + b_r)
        b_grad.setColorAt(0.0, QColor("#EF4444"))
        b_grad.setColorAt(1.0, QColor("#B91C1C"))
        painter.setBrush(b_grad)
        painter.setPen(QPen(QColor("#FFFFFF"), s * 0.016))
        painter.drawEllipse(QPointF(b_cx, b_cy), b_r, b_r)
        # glossy top half
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 255, 255, 55))
        painter.drawPie(QRectF(b_cx - b_r, b_cy - b_r, b_r * 2, b_r * 2),
                        0, 180 * 16)
        # X glyph
        fx = QFont()
        fx.setPointSizeF(max(5.0, s * 0.115))
        fx.setBold(True)
        painter.setFont(fx)
        painter.setPen(QPen(QColor("#FFFFFF")))
        painter.drawText(QRectF(b_cx - b_r, b_cy - b_r, b_r * 2, b_r * 2),
                         Qt.AlignmentFlag.AlignCenter, "X")

    painter.restore()


def paint_globe_ring(painter: QPainter, rect: QRectF,
                     color: str = "primary") -> None:
    """Decorative globe grid for splash/illustration contexts."""
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    c = QColor(theme.COLORS.get(color, theme.COLORS["primary"]))
    c.setAlpha(60)
    pen = QPen(c, 1.1)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawEllipse(rect)
    w = rect.width()
    painter.drawEllipse(QRectF(rect.left() + w * 0.22, rect.top(),
                               w * 0.56, rect.height()))
    painter.drawEllipse(QRectF(rect.left() + w * 0.40, rect.top(),
                               w * 0.20, rect.height()))
    cy = rect.center().y()
    painter.drawLine(QPointF(rect.left(), cy), QPointF(rect.right(), cy))
    # outer dashed halo
    halo = QColor(theme.COLORS.get(color, theme.COLORS["primary"]))
    halo.setAlpha(36)
    pen = QPen(halo, 1.0)
    pen.setStyle(Qt.PenStyle.DashLine)
    pen.setDashPattern([2, 6])
    painter.setPen(pen)
    painter.drawEllipse(rect.adjusted(-9, -9, 9, 9))
    painter.restore()
