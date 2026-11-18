"""
AegisX — boot splash screen (premium 3D edition).

Branded, animated startup display (~2 seconds minimum): layered emblem
with a glowing progress halo, animated shield entrance, staged status
messages with indicator dots, percentage readout and a smooth fade-out
transition into the main window.
"""

from __future__ import annotations

import math
import time

from PySide6.QtCore import (
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    Qt,
    QTimer,
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

from ..styles import theme
from ..version import APP_AUTHOR, APP_TAGLINE, APP_VERSION
from .logo import paint_globe_ring, paint_shield

STAGES = [
    "Initializing security environment…",
    "Loading intelligence modules…",
    "Connecting local database…",
    "Preparing analysis workspace…",
    "Finalizing command center…",
]


class SplashScreen(QWidget):
    """Branded boot splash with animated progress halo."""

    def center_on_screen(self) -> None:
        """Place the splash at the center of its current screen."""
        screen = self.screen()
        if screen:
            self.move(screen.availableGeometry().center() - self.rect().center())

    finished = Signal()

    def __init__(self, *, min_ms: int = 2000) -> None:
        super().__init__(None)
        self.setWindowFlags(
            Qt.WindowType.SplashScreen
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setFixedSize(660, 430)
        self._start = time.monotonic()
        self._min_ms = min_ms
        self._progress = 0.0
        self._stage = 0
        self._closing = False

        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

        self._stage_timer = QTimer(self)
        self._stage_timer.setInterval(max(1, min_ms // len(STAGES)))
        self._stage_timer.timeout.connect(self._advance_stage)
        self._stage_timer.start()

    # ---------------------------------------------------------------- anim
    def _tick(self) -> None:
        self._progress = min(1.0, self._progress + 0.022)
        self.update()

    def _advance_stage(self) -> None:
        self._stage = min(len(STAGES) - 1, self._stage + 1)
        self.update()

    # ---------------------------------------------------------------- paint
    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # layered background: soft vertical gradient + corner glow washes
        bg = QLinearGradient(0, 0, 0, h)
        bg.setColorAt(0.0, QColor("#FFFFFF"))
        bg.setColorAt(0.72, QColor("#F8FAFC"))
        bg.setColorAt(1.0, QColor("#EEF2F7"))
        p.fillRect(self.rect(), QBrush(bg))

        p.setPen(Qt.PenStyle.NoPen)
        glow1 = QRadialGradient(QPointF(-60, h - 40), 340)
        glow1.setColorAt(0.0, QColor(220, 38, 38, 26))
        glow1.setColorAt(1.0, QColor(220, 38, 38, 0))
        p.setBrush(glow1)
        p.drawEllipse(QPointF(-60, h - 40), 340, 340)
        glow2 = QRadialGradient(QPointF(w + 30, -40), 320)
        glow2.setColorAt(0.0, QColor(239, 68, 68, 22))
        glow2.setColorAt(1.0, QColor(239, 68, 68, 0))
        p.setBrush(glow2)
        p.drawEllipse(QPointF(w + 30, -40), 320, 320)

        cx = w / 2

        # ---- emblem block ---------------------------------------------------
        emblem_cy = 148
        halo_r = 84

        # ambient red wash behind the emblem
        wash = QRadialGradient(QPointF(cx, emblem_cy), halo_r * 1.8)
        wash.setColorAt(0.0, QColor(220, 38, 38, 30))
        wash.setColorAt(0.6, QColor(239, 68, 68, 10))
        wash.setColorAt(1.0, QColor(239, 68, 68, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(wash)
        p.drawEllipse(QPointF(cx, emblem_cy), halo_r * 1.8, halo_r * 1.8)

        # decorative globe grid
        paint_globe_ring(p, QRectF(cx - 108, emblem_cy - 108, 216, 216),
                         "primary")

        # ---- progress halo: track + glowing gradient arc ---------------------
        pr = self._progress
        ease = 1.0 - pow(1.0 - pr, 3)          # ease-out cubic
        span_deg = int(360 * 16 * ease)
        arc_rect = QRectF(cx - halo_r, emblem_cy - halo_r,
                          halo_r * 2, halo_r * 2)

        p.setPen(QPen(QColor("#E6EBF1"), 6, Qt.PenStyle.SolidLine,
                      Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(arc_rect)

        # outer soft glow pass
        t = self._progress * 100.0
        sweep_phase = (t * 2.2) % 360.0
        glow_pen = QPen(QColor(239, 68, 68, 60), 11)
        p.setPen(glow_pen)
        p.drawArc(arc_rect, 90 * 16, span_deg)
        # solid gradient pass
        arc_grad = QLinearGradient(arc_rect.topLeft(), arc_rect.bottomRight())
        arc_grad.setColorAt(0.0, QColor("#EF4444"))
        arc_grad.setColorAt(0.5, QColor(theme.COLORS["primary"]))
        arc_grad.setColorAt(1.0, QColor("#B91C1C"))
        p.setPen(QPen(QBrush(arc_grad), 6, Qt.PenStyle.SolidLine,
                      Qt.PenCapStyle.RoundCap))
        p.drawArc(arc_rect, 90 * 16, span_deg)
        # comet head riding the arc
        head_ang = math.radians(90 - 360 * ease)
        hx = cx + halo_r * math.cos(head_ang)
        hy = emblem_cy - halo_r * math.sin(head_ang)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#FFFFFF"))
        p.drawEllipse(QPointF(hx, hy), 5.2, 5.2)
        p.setBrush(QColor(239, 68, 68, 70))
        p.drawEllipse(QPointF(hx, hy), 9.5, 9.5)

        # ---- shield with entrance scale --------------------------------------
        appear = min(1.0, pr * 3.2)
        scale = 0.88 + 0.12 * (1 - pow(1 - appear, 3))
        shield_s = 104 * scale
        paint_shield(p, QRectF(cx - shield_s / 2, emblem_cy - shield_s / 2,
                               shield_s, shield_s),
                     size=shield_s * 0.94, badge_x=True)

        # ---- brand title ------------------------------------------------------
        f = p.font()
        f.setPointSizeF(28)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QPen(QColor(theme.COLORS["text"])))
        title_rect = QRectF(0, 262, w, 48)
        p.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, f"Aegis{''}")
        fm = p.fontMetrics()
        w_full = fm.horizontalAdvance("Aegis")
        p.setPen(QPen(QColor(theme.COLORS["primary"])))
        p.drawText(QRectF((w + w_full) / 2 - 8, 262, 46, 48),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   "X")

        # ---- tagline -----------------------------------------------------------
        f.setPointSizeF(10.5)
        f.setBold(False)
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3.4)
        p.setFont(f)
        p.setPen(QPen(QColor(theme.COLORS["text_muted"])))
        p.drawText(QRectF(0, 308, w, 22),
                   Qt.AlignmentFlag.AlignCenter, APP_TAGLINE.upper())

        # ---- progress bar + percentage ------------------------------------------
        bar_w, bar_h = 320, 6
        bx = (w - bar_w) / 2
        by = 340
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#E6EBF1"))
        p.drawRoundedRect(QRectF(bx, by, bar_w, bar_h), 3, 3)
        head_x = bx + bar_w * ease
        sweep_w = bar_w * 0.30
        x0 = max(bx, min(bx + bar_w - sweep_w, head_x - sweep_w / 2))
        bar_grad = QLinearGradient(bx, by, bx + bar_w, by)
        bar_grad.setColorAt(0.0, QColor("#EF4444"))
        bar_grad.setColorAt(1.0, QColor("#B91C1C"))
        p.setBrush(QBrush(bar_grad))
        p.drawRoundedRect(QRectF(x0, by, min(sweep_w, bx + bar_w - x0), bar_h), 3, 3)
        # leading knob
        p.setBrush(QColor(theme.COLORS["primary"]))
        p.drawEllipse(QPointF(head_x, by + bar_h / 2), 4.4, 4.4)

        f.setPointSizeF(9.5)
        f.setBold(True)
        f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0)
        p.setFont(f)
        p.setPen(QPen(QColor("#B91C1C")))
        p.drawText(QRectF(bx + bar_w + 10, by - 7, 52, 20),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   f"{int(ease * 100)}%")

        # ---- stage text + dots ---------------------------------------------------
        f.setPointSizeF(10.5)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QPen(QColor(theme.COLORS["text_secondary"])))
        p.drawText(QRectF(0, 358, w, 22),
                   Qt.AlignmentFlag.AlignCenter, STAGES[self._stage])

        dot_y = 384
        n = len(STAGES)
        dot_gap = 16
        start_x = cx - (n - 1) * dot_gap / 2
        for i in range(n):
            on = i <= self._stage
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(theme.COLORS["primary"]) if on
                       else QColor("#DBE1EA"))
            p.drawEllipse(QPointF(start_x + i * dot_gap, dot_y),
                          3.4 if on else 3.0, 3.4 if on else 3.0)

        # ---- footer ----------------------------------------------------------------
        f.setPointSizeF(9)
        f.setBold(False)
        p.setFont(f)
        p.setPen(QPen(QColor(theme.COLORS["text_muted"])))
        p.drawText(QRectF(0, h - 30, w, 20),
                   Qt.AlignmentFlag.AlignCenter,
                   f"v{APP_VERSION} · by {APP_AUTHOR}")
        p.drawText(QRectF(0, h - 13, w, 16),
                   Qt.AlignmentFlag.AlignCenter, "Designed for Kali Linux")

    # ---------------------------------------------------------------- close
    def finish(self) -> None:
        """Close when minimum display time elapsed; emits finished."""
        elapsed = (time.monotonic() - self._start) * 1000
        remaining = max(0, self._min_ms - elapsed)
        QTimer.singleShot(remaining, self._fade_out)

    def _fade_out(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._timer.stop()
        self._stage_timer.stop()
        self._anim = QPropertyAnimation(self, b"windowOpacity")
        self._anim.setDuration(280)
        self._anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self._anim.finished.connect(self._really_close)
        self._anim.start()

    def _really_close(self) -> None:
        self.finished.emit()
        self.close()
        self.deleteLater()
