"""
AegisX — toast notification system.

Elegant, auto-dismissing notifications stacked top-right over the content
area, with slide+fade animation and severity accents.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ..styles import theme
from .components import add_shadow, label
from .icons import icon

KIND_ICONS = {"info": "info", "success": "check", "warning": "alert",
              "critical": "alert", "error": "alert"}
KIND_ACCENTS = {"info": theme.COLORS["info"], "success": theme.COLORS["success"],
                "warning": theme.COLORS["warning"], "critical": theme.COLORS["critical"],
                "error": theme.COLORS["critical"]}


class Toast(QFrame):
    dismissed = Signal(object)

    def __init__(self, kind: str, title: str, message: str,
                 timeout_ms: int = 4200) -> None:
        super().__init__()
        self.setObjectName("Toast")
        self.setFixedWidth(340)
        add_shadow(self, blur=26, alpha=36, y_offset=6)
        accent = KIND_ACCENTS.get(kind, KIND_ACCENTS["info"])

        self.setStyleSheet(
            "QFrame#Toast { background: #FFFFFF; border: 1px solid "
            f"{theme.COLORS['border']}; border-left: 4px solid {accent};"
            " border-radius: 12px; }"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 11, 14, 11)
        lay.setSpacing(3)

        head = QHBoxLayout()
        head.setSpacing(9)
        ic = QLabel()
        ic.setPixmap(icon(KIND_ICONS.get(kind, "info"), accent, 16).pixmap(16, 16))
        head.addWidget(ic)
        head.addWidget(label(title, "ToastTitle", wordwrap=False))
        head.addStretch(1)
        lay.addLayout(head)

        if message:
            m = label(message, "ToastBody", wordwrap=True)
            lay.addWidget(m)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(timeout_ms)
        self._timer.timeout.connect(self.dismiss)

        # enter animation
        self._anim = QPropertyAnimation(self, b"pos")
        self._anim.setDuration(260)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade = QPropertyAnimation(self, b"windowOpacity")
        self._fade.setDuration(200)
        self._fade.setEasingCurve(QEasingCurve.Type.InQuad)

    def start(self, target_pos) -> None:
        self.show()
        start = target_pos + self.rect().topRight() - self.rect().topLeft()
        self.move(start.x() + 34, target_pos.y())
        self._anim.setStartValue(self.pos())
        self._anim.setEndValue(target_pos)
        self._anim.start()
        self._timer.start()

    def mousePressEvent(self, _e) -> None:  # noqa: N802
        self.dismiss()

    def dismiss(self) -> None:
        self._timer.stop()
        self._fade.finished.connect(lambda: self.dismissed.emit(self))
        self._fade.start()


class ToastHost(QWidget):
    """Transparent overlay hosting toast notifications."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self._toasts: list[Toast] = []
        self.hide()

    def notify(self, kind: str, title: str, message: str = "",
               timeout_ms: int = 4200) -> None:
        toast = Toast(kind, title, message, timeout_ms)
        toast.dismissed.connect(self._on_dismissed)
        self._toasts.append(toast)
        self.resize(self.parentWidget().size())
        self.show()
        self.raise_()
        target = self._next_position(toast)
        toast.start(target)
        self._reposition()

    def _next_position(self, toast: Toast) -> QPoint:
        x = self.width() - toast.width() - 22
        y = 14 + sum(t.height() + 10 for t in self._toasts if t is not toast and t.isVisible())
        return QPoint(x, y)

    def _reposition(self) -> None:
        y = 14
        for t in self._toasts:
            if not t.isVisible():
                continue
            x = self.width() - t.width() - 22
            anim = QPropertyAnimation(t, b"pos")
            anim.setDuration(220)
            anim.setEasingCurve(QEasingCurve.Type.OutCubic)
            anim.setStartValue(t.pos())
            anim.setEndValue(QPoint(x, y))
            anim.start()
            y += t.height() + 10
            # keep reference to prevent GC mid-animation
            t._reposition_anim = anim  # type: ignore[attr-defined]

    def _on_dismissed(self, toast: Toast) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        toast.deleteLater()
        self._reposition()
        if not self._toasts:
            self.hide()

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._reposition()
