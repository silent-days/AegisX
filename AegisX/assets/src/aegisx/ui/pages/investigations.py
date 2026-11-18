"""
AegisX — Investigation Workspace.

Multi-panel analyst workspace: investigation list, detail editor, item
table, timestamped notes and report generation.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.services import ServiceHub
from ...workers import TaskManager
from ..components import (
    Badge,
    Card,
    DataTable,
    DangerButton,
    EmptyState,
    GhostButton,
    KVWidget,
    PrimaryButton,
    label,
    relative_time,
)
from ..dialogs import ReportDialog
from .base_page import PageBase


class InvestigationsPage(PageBase):
    title = "Investigation Workspace"
    subtitle = "Structured case management for your threat intelligence analysis."
    page_key = "investigations"

    def build(self) -> None:
        self.maybe_demo_banner()

        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(14)

        # ------------------------------------------------------- list panel
        card_list = Card()
        card_list.layout().addWidget(label("Investigations", "H3"))
        self.list_search = QLineEdit()
        self.list_search.setPlaceholderText("Filter…")
        self.list_search.textChanged.connect(lambda _t: self._fill_list())
        card_list.layout().addWidget(self.list_search)
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._on_select)
        self.list.setMinimumWidth(240)
        card_list.layout().addWidget(self.list, 1)
        btn_new = PrimaryButton("New investigation", "plus")
        btn_new.clicked.connect(self._new_investigation)
        card_list.layout().addWidget(btn_new)
        btn_del = DangerButton("Delete", "trash")
        btn_del.clicked.connect(self._delete_investigation)
        card_list.layout().addWidget(btn_del)
        rl.addWidget(card_list, 1)

        # ------------------------------------------------------- detail panel
        detail_card = Card()
        detail_card.layout().addWidget(label("Case Details", "H3"))
        meta_row = QHBoxLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Investigation name")
        meta_row.addWidget(self.name_edit, 1)
        self.status_combo = QComboBox()
        self.status_combo.addItems(["open", "active", "closed"])
        meta_row.addWidget(self.status_combo)
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["low", "medium", "high", "critical"])
        meta_row.addWidget(self.priority_combo)
        detail_card.layout().addLayout(meta_row)

        self.meta_lbl = label("", "Muted")
        detail_card.layout().addWidget(self.meta_lbl)
        self.desc_edit = QPlainTextEdit()
        self.desc_edit.setPlaceholderText("Case description / objectives…")
        self.desc_edit.setFixedHeight(70)
        detail_card.layout().addLayout(self._wrap(self.desc_edit))

        item_head = QHBoxLayout()
        item_head.addWidget(label("Indicators", "H3"))
        item_head.addStretch(1)
        btn_add_item = GhostButton("Add indicator", "plus")
        btn_add_item.clicked.connect(self._add_item)
        item_head.addWidget(btn_add_item)
        btn_remove_item = GhostButton("Remove selected", "trash")
        btn_remove_item.clicked.connect(self._remove_item)
        item_head.addWidget(btn_remove_item)
        detail_card.layout().addLayout(item_head)

        self.items_table = DataTable(["Indicator", "Type", "Severity", "Risk", "Added"])
        self.items_table.setMinimumHeight(180)
        detail_card.layout().addWidget(self.items_table, 1)

        note_row = QHBoxLayout()
        self.note_edit = QLineEdit()
        self.note_edit.setPlaceholderText("Add timestamped analyst note…")
        self.note_edit.returnPressed.connect(self._add_note)
        note_row.addWidget(self.note_edit, 1)
        btn_note = PrimaryButton("Add note", "edit")
        btn_note.clicked.connect(self._add_note)
        note_row.addWidget(btn_note)
        detail_card.layout().addLayout(note_row)

        self.notes_list = QListWidget()
        self.notes_list.setMaximumHeight(120)
        detail_card.layout().addWidget(self.notes_list)

        actions = QHBoxLayout()
        btn_save = PrimaryButton("Save changes", "save")
        btn_save.clicked.connect(self._save)
        actions.addWidget(btn_save)
        btn_report = GhostButton("Generate report", "report")
        btn_report.clicked.connect(self._generate_report)
        actions.addWidget(btn_report)
        actions.addStretch(1)
        detail_card.layout().addLayout(actions)
        rl.addWidget(detail_card, 2)

        # ------------------------------------------------------- context panel
        context_card = Card()
        context_card.layout().addWidget(label("Selected Indicator", "H3"))
        self.context = KVWidget()
        context_card.layout().addWidget(self.context, 1)
        self.btn_investigate = PrimaryButton("Investigate further", "target")
        self.btn_investigate.setEnabled(False)
        self.btn_investigate.clicked.connect(self._investigate_item)
        context_card.layout().addWidget(self.btn_investigate)
        rl.addWidget(context_card, 1)

        self.body_lay.addWidget(row, 1)

        self.items_table.row_selected.connect(self._on_item_row)
        self._current_id: int | None = None

    @staticmethod
    def _wrap(widget) -> QHBoxLayout:
        lay = QHBoxLayout()
        lay.addWidget(widget, 1)
        return lay

    # ------------------------------------------------------------------ list
    def refresh(self) -> None:
        self._fill_list()

    def _fill_list(self) -> None:
        hub = self.hub()
        self.list.blockSignals(True)
        self.list.clear()
        query = self.list_search.text().strip().lower()
        for inv in hub.repo.list_investigations():
            if query and query not in inv["name"].lower():
                continue
            item = QListWidgetItem(f"{inv['name']}  ·  {inv['status']}  ·  {inv['item_count']} indicators")
            item.setData(Qt.ItemDataRole.UserRole, inv["id"])
            self.list.addItem(item)
        self.list.blockSignals(False)
        if self.list.count() and self._current_id is None:
            self.list.setCurrentRow(0)
        elif self._current_id is not None:
            match = [r for r in range(self.list.count())
                     if self.list.item(r).data(Qt.ItemDataRole.UserRole) == self._current_id]
            if match:
                self.list.setCurrentRow(match[0])
            else:
                self._current_id = None

    def _on_select(self, row: int) -> None:
        item = self.list.item(row)
        if not item:
            return
        inv_id = item.data(Qt.ItemDataRole.UserRole)
        self._current_id = inv_id
        self._load_detail(inv_id)

    def _load_detail(self, inv_id: int) -> None:
        hub = self.hub()
        inv = hub.repo.get_investigation(inv_id)
        if not inv:
            return
        self.name_edit.setText(inv["name"])
        self.desc_edit.setPlainText(inv["description"])
        self.status_combo.setCurrentText(inv["status"])
        self.priority_combo.setCurrentText(inv["priority"])
        self.meta_lbl.setText(
            f"Created {relative_time(inv['created_at'])} · updated {relative_time(inv['updated_at'])}"
            f" · analyst {inv['analyst']} · priority {inv['priority']}")

        items = hub.repo.investigation_items(inv_id)
        self.items_table.set_rows(
            [[i["value"], i["type"].upper(), i["severity"].upper(),
              f"{i['risk_score']}/100", relative_time(i["item_added_at"])] for i in items],
            items)

        self.notes_list.clear()
        for note in reversed(inv.get("notes") or []):
            self.notes_list.addItem(f"[{relative_time(note['ts'])}] {note['author']}: {note['text']}")

    # -------------------------------------------------------------- actions
    def _new_investigation(self) -> None:
        from ..dialogs.common import TextDialog

        dlg = TextDialog(self, "New investigation name", placeholder="e.g. Perimeter triage — week 42")
        if not dlg.exec():
            return
        hub = self.hub()
        inv_id = hub.repo.create_investigation(dlg.value())
        hub.events.publish("investigation.created", f"Investigation '{dlg.value()}' created",
                           severity="success")
        self._current_id = inv_id
        self.refresh()

    def _delete_investigation(self) -> None:
        if self._current_id is None:
            return
        from ..dialogs.common import ConfirmDialog

        dlg = ConfirmDialog(self, "Delete investigation",
                            "Delete this investigation and its item links? Indicators are kept.",
                            confirm_text="Delete")
        if not dlg.accepted():
            return
        hub = self.hub()
        hub.repo.delete_investigation(self._current_id)
        self._current_id = None
        self.refresh()

    def _save(self) -> None:
        if self._current_id is None:
            return
        hub = self.hub()
        hub.repo.update_investigation(
            self._current_id,
            name=self.name_edit.text().strip() or "Untitled",
            description=self.desc_edit.toPlainText().strip(),
            status=self.status_combo.currentText(),
            priority=self.priority_combo.currentText(),
        )
        hub.events.publish("investigation.updated", "Investigation saved", severity="success")
        self.refresh()

    def _add_item(self) -> None:
        if self._current_id is None:
            return
        from ..dialogs.common import TextDialog

        dlg = TextDialog(self, "Add indicator to investigation",
                         placeholder="IP, domain, URL or hash")
        if not dlg.exec():
            return
        hub = self.hub()
        ind = hub.repo.get_indicator_by_value(dlg.value())
        if not ind:
            # analyze then add (worker)
            TaskManager.get().submit(
                hub.engine.lookup, dlg.value(),
                description="inv-lookup",
                on_done=lambda rep: self._add_item_after_lookup(rep, dlg.value()),
                on_error=lambda err: QMessageBox.warning(self, "Lookup failed", err[:200]),
            )
            return
        hub.repo.add_investigation_item(self._current_id, ind["id"])
        self._load_detail(self._current_id)
        self.refresh()

    def _add_item_after_lookup(self, report, value: str) -> None:
        if not report:
            return
        hub = self.hub()
        ind = hub.repo.get_indicator_by_value(value)
        if ind and self._current_id is not None:
            hub.repo.add_investigation_item(self._current_id, ind["id"])
        self._load_detail(self._current_id)
        self.refresh()

    def _remove_item(self) -> None:
        if self._current_id is None:
            return
        row = self.items_table.currentRow()
        if row < 0:
            return
        payload = self.items_table._payloads[row]
        self.hub().repo.remove_investigation_item(self._current_id, payload["id"])
        self._load_detail(self._current_id)

    def _add_note(self) -> None:
        if self._current_id is None:
            return
        text = self.note_edit.text().strip()
        if not text:
            return
        hub = self.hub()
        hub.repo.add_note(self._current_id, hub.settings.get("analyst_name") or "analyst", text)
        self.note_edit.clear()
        self._load_detail(self._current_id)

    def _on_item_row(self, payload: dict) -> None:
        self.context.set_items([
            ("Indicator", payload.get("value", "")),
            ("Type", payload.get("type", "").upper()),
            ("Severity", payload.get("severity", "").upper()),
            ("Risk", f"{payload.get('risk_score', 0)}/100"),
            ("Country", payload.get("country") or "—"),
            ("ASN", payload.get("asn") or "—"),
        ], mono_keys=("Indicator",))
        self.btn_investigate.setEnabled(True)
        self._selected_value = payload.get("value")

    def _investigate_item(self) -> None:
        if not getattr(self, "_selected_value", None):
            return
        win = self.window()
        value = self._selected_value
        is_ip = all(p.isdigit() for p in value.split(".") if p) and value.count(".") == 3
        key = "ip_investigation" if is_ip else "domain_intelligence"
        win.navigate(key)
        page = win.page(key)
        if page and hasattr(page, "set_input"):
            page.set_input(value)
            page.run_lookup()

    def _generate_report(self) -> None:
        if self._current_id is None:
            QMessageBox.information(self, "No investigation selected",
                                    "Create or select an investigation first.")
            return
        dlg = ReportDialog(self, investigation_id=self._current_id)
        if not dlg.exec() or not dlg.result:
            return
        inv_id, fmt = dlg.result
        hub = self.hub()
        TaskManager.get().submit(
            self._build_report, inv_id, fmt,
            description="report-generation",
            on_done=lambda path: self._report_done(path),
            on_error=lambda err: QMessageBox.critical(self, "Report failed", err[:300]),
        )

    @staticmethod
    def _build_report(inv_id: int, fmt: str):
        from ...reports import build_report, export_report

        hub = ServiceHub.get()
        payload = build_report(hub.repo, investigation_id=inv_id)
        path = export_report(payload, fmt)
        return path

    def _report_done(self, path) -> None:
        hub = self.hub()
        hub.repo.add_report(path.name, str(path), path.suffix.lstrip("."),
                            investigation_id=self._current_id)
        hub.events.publish("report.generated", f"Report generated: {path.name}",
                           severity="success")
        win = self.window()
        if hasattr(win, "navigate"):
            win.navigate("reports")


def _unused():  # keep module namespace clean
    return None
