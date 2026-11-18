"""
AegisX — Reports page.

Lists generated reports with open/reveal/delete actions and report
generation entry point.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ..components import (
    Badge,
    Card,
    DataTable,
    EmptyState,
    GhostButton,
    PrimaryButton,
    label,
    relative_time,
)
from ..dialogs import ReportDialog
from .base_page import PageBase


class ReportsPage(PageBase):
    title = "Reports"
    subtitle = "Professional, self-contained intelligence reports generated from your work."
    page_key = "reports"

    def build(self) -> None:
        self.maybe_demo_banner()

        actions = QWidget()
        al = QHBoxLayout(actions)
        al.setContentsMargins(0, 0, 0, 0)
        al.addStretch(1)
        btn_generate = PrimaryButton("Generate report", "report")
        btn_generate.clicked.connect(self._generate)
        al.addWidget(btn_generate)
        self.body_lay.addWidget(actions)

        card = Card()
        self.table = DataTable(["Title", "Investigation", "Format", "Created", "Size", "Actions"])
        self.table.row_double.connect(self._open_report)
        card.layout().addWidget(self.table, 1)
        self.body_lay.addWidget(card, 1)

        self.empty = EmptyState(
            "No reports yet",
            "Generate your first report from an investigation — branded, evidence-driven "
            "and ready to share or print to PDF.",
            icon_name="report",
            action=PrimaryButton("Generate report", "report"),
        )

        info = label(
            "HTML reports are fully self-contained (inline styles + embedded logo) and can be "
            "printed to PDF from any browser. Files are stored in "
            "~/.local/share/aegisx/reports/", "Muted")
        self.body_lay.addWidget(info)

    def refresh(self) -> None:
        hub = self.hub()
        reports = hub.repo.list_reports()
        rows = []
        for r in reports:
            size = "?"
            try:
                size = f"{Path(r['path']).stat().st_size / 1024:.0f} KB"
            except OSError:
                size = "missing"
            rows.append([r["title"], r["format"].upper(), r["created"][:16].replace("T", " "),
                         size, r["path"], ""])
        self.table.set_rows(rows, reports)
        if not reports:
            self.table.hide()
            if self.empty.parent() is None:
                self.body_lay.addWidget(self.empty)
            self.empty.show()
        else:
            if self.empty.parent() is not None:
                self.empty.hide()
            self.table.show()
        self.maybe_demo_banner()

    def _generate(self) -> None:
        dlg = ReportDialog(self)
        if not dlg.exec() or not dlg.result:
            return
        inv_id, fmt = dlg.result
        from ...reports import build_report, export_report
        from ...workers import TaskManager

        hub = self.hub()
        TaskManager.get().submit(
            lambda: export_report(build_report(hub.repo, investigation_id=inv_id), fmt),
            description="report-generation",
            on_done=self._generated,
            on_error=lambda err: QMessageBox.critical(self, "Report failed", err[:300]),
        )

    def _generated(self, path) -> None:
        hub = self.hub()
        hub.repo.add_report(path.stem.replace("-", " "), str(path),
                            path.suffix.lstrip("."))
        hub.events.publish("report.generated", f"Report ready: {path.name}", severity="success")
        self.refresh()

    def _open_report(self, report: dict) -> None:
        path = Path(report.get("path", ""))
        if not path.is_file():
            QMessageBox.warning(self, "Missing file",
                                "The report file no longer exists on disk.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _delete_report(self, report: dict) -> None:
        hub = self.hub()
        hub.repo.delete_report(report["id"])
        self.refresh()
