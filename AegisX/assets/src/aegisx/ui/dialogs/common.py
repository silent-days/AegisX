"""AegisX — common dialogs (confirm, text input)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ..components import DangerButton, PrimaryButton, label


class ConfirmDialog(QDialog):
    """Branded confirmation dialog (used for destructive actions).

    The dialog executes modally inside the constructor (backwards-compatible
    pattern). Callers must check :meth:`accepted` (or ``result()``) before
    performing the destructive action.
    """

    def __init__(self, parent: QWidget | None, title: str, message: str,
                 *, danger: bool = True, confirm_text: str = "Confirm",
                 cancel_text: str = "Cancel") -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedWidth(440)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(12)

        t = label(title, "H2")
        lay.addWidget(t)
        m = QLabel(message)
        m.setWordWrap(True)
        m.setStyleSheet("color: #64748B; font-size: 13px;")
        lay.addWidget(m)

        row = QHBoxLayout()
        row.addStretch(1)
        from ..components import GhostButton

        btn_cancel = GhostButton(cancel_text)
        btn_cancel.clicked.connect(self.reject)
        row.addWidget(btn_cancel)
        btn_ok = DangerButton(confirm_text) if danger else PrimaryButton(confirm_text)
        btn_ok.clicked.connect(self.accept)
        row.addWidget(btn_ok)
        lay.addLayout(row)

        self.exec()
        self._accepted = self.result() == QDialog.DialogCode.Accepted

    def accepted(self) -> bool:
        """True when the user confirmed (after the dialog closed)."""
        return getattr(self, "_accepted", False)


class TextDialog(QDialog):
    """Single text input dialog (names, tags…)."""

    def __init__(self, parent: QWidget | None, title: str, placeholder: str = "",
                 initial: str = "", parent_widget: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setFixedWidth(430)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(10)
        lay.addWidget(label(title, "H2"))
        self.edit = QLineEdit(initial)
        self.edit.setPlaceholderText(placeholder)
        self.edit.textChanged.connect(self._validate)
        self.edit.returnPressed.connect(self._ok)
        lay.addWidget(self.edit)
        self.error = label("", "Muted")
        self.error.setStyleSheet("color: #DC2626;")
        lay.addWidget(self.error)

        row = QHBoxLayout()
        row.addStretch(1)
        from ..components import GhostButton

        btn_cancel = GhostButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        row.addWidget(btn_cancel)
        self.btn_ok = PrimaryButton("OK")
        self.btn_ok.clicked.connect(self._ok)
        row.addWidget(self.btn_ok)
        lay.addLayout(row)
        self._validate()

    def _validate(self) -> None:
        ok = len(self.edit.text().strip()) >= 3
        self.btn_ok.setEnabled(ok)
        self.error.setText("" if ok else "Enter at least 3 characters.")

    def _ok(self) -> None:
        if self.edit.text().strip():
            self.accept()

    def value(self) -> str:
        return self.edit.text().strip()
