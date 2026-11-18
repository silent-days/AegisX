"""AegisX — report generation dialog."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
)

from ...core.services import ServiceHub
from ..components import Card, GhostButton, PrimaryButton, label


class ReportDialog(QDialog):
    """Choose investigation + format and generate a branded report."""

    def __init__(self, parent: QWidget | None, investigation_id: int | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generate Intelligence Report")
        self.setModal(True)
        self.setFixedWidth(500)
        self.result = None  # (path, format) when accepted

        hub = ServiceHub.get()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)
        lay.addWidget(label("Generate Intelligence Report", "H2"))
        lay.addWidget(label(
            "Reports are professional, self-contained documents with evidence factors, "
            "source findings and MITRE ATT&CK associations.", "Muted"))

        card = Card()
        card.layout().addWidget(label("Investigation", "H3"))
        self.inv_combo = QComboBox()
        for inv in hub.repo.list_investigations():
            self.inv_combo.addItem(f"{inv['name']}  ({inv['item_count']} indicators)",
                                   inv["id"])
        if investigation_id:
            idx = self.inv_combo.findData(investigation_id)
            if idx >= 0:
                self.inv_combo.setCurrentIndex(idx)
        card.layout().addWidget(self.inv_combo)
        card.layout().addWidget(label("Format", "H3"))
        self.fmt_combo = QComboBox()
        self.fmt_combo.addItem("HTML (print-ready)", "html")
        self.fmt_combo.addItem("JSON (machine-readable)", "json")
        card.layout().addWidget(self.fmt_combo)
        lay.addWidget(card)

        note = label("Tip: you can print HTML reports to PDF directly from any browser.", "Muted")
        lay.addWidget(note)

        row = QHBoxLayout()
        row.addStretch(1)
        cancel = GhostButton("Cancel")
        cancel.clicked.connect(self.reject)
        row.addWidget(cancel)
        gen = PrimaryButton("Generate", "report")
        gen.clicked.connect(self._generate)
        row.addWidget(gen)
        lay.addLayout(row)

    def _generate(self) -> None:
        inv_id = self.inv_combo.currentData()
        fmt = self.fmt_combo.currentData()
        if inv_id is None:
            self.reject()
            return
        self.result = (int(inv_id), fmt)
        self.accept()
