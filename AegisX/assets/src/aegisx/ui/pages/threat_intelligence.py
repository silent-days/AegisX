"""
AegisX — Threat Intelligence page (advanced IOC manager).

Every tracked indicator across all sources in one searchable table, now
with full lifecycle control:

* per-row quick **Remove** button and a right-click context menu
  (details / copy / re-analyze / tag / remove)
* multi-select bulk operations — remove selected, re-scan selected,
  tag selected, export selected (CSV)
* an **Advanced filters** panel — source, tag, minimum risk score and
  recency window
* **Remove all filtered** — bulk cleanup of everything matching the
  current filters, guarded by a typed confirmation
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from ...core.services import ServiceHub
from ...utils.exports import export_indicators_csv, import_indicators_csv
from ..components import (
    Card,
    DataTable,
    DangerButton,
    GhostButton,
    PrimaryButton,
    label,
    relative_time,
)
from .base_page import PageBase

PAGE_SIZE = 40

TYPE_MAP = {0: "", 1: "ip", 2: "ipv6", 3: "domain", 4: "url", 5: "hash"}
SEV_MAP = {0: "", 1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
ORDER_MAP = {0: "risk", 1: "recent", 2: "confidence", 3: "value"}
DAYS_MAP = {0: 0, 1: 1, 2: 7, 3: 30}


def _combo(items: list[str]) -> QComboBox:
    c = QComboBox()
    c.addItems(items)
    return c


class ThreatIntelligencePage(PageBase):
    title = "Threat Intelligence"
    subtitle = ("Track, filter, re-analyze and remove every indicator — "
                "with advanced bulk operations.")
    page_key = "threat_intelligence"

    def build(self) -> None:
        self.maybe_demo_banner()

        # toolbar ---------------------------------------------------------
        bar = Card()
        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search indicators… (e.g. 192.0.2, phishing, AS17557)")
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(lambda: self.refresh(reset_page=True))
        row.addWidget(self.search, 1)
        self.type_combo = _combo(
            ["All types", "IP", "IPv6", "Domain", "URL", "Hash"])
        self.type_combo.currentIndexChanged.connect(
            lambda: self.refresh(reset_page=True))
        row.addWidget(self.type_combo)
        self.sev_combo = _combo(
            ["All severities", "Critical", "High", "Medium", "Low", "Info"])
        self.sev_combo.currentIndexChanged.connect(
            lambda: self.refresh(reset_page=True))
        row.addWidget(self.sev_combo)
        self.order_combo = _combo(
            ["Sort: Risk", "Sort: Recent", "Sort: Confidence", "Sort: Value"])
        self.order_combo.currentIndexChanged.connect(
            lambda: self.refresh(reset_page=True))
        row.addWidget(self.order_combo)
        self.btn_adv = GhostButton("Advanced", "filter")
        self.btn_adv.setCheckable(True)
        self.btn_adv.toggled.connect(self._toggle_advanced)
        row.addWidget(self.btn_adv)
        bar.layout().addLayout(row)

        # ---- advanced filter panel (hidden by default) ------------------
        self.adv_panel = QFrame()
        self.adv_panel.setObjectName("AdvancedFilters")
        self.adv_panel.setStyleSheet(
            "QFrame#AdvancedFilters { background: #F8FAFC;"
            " border: 1px solid #EEF1F5; border-radius: 10px; }")
        adv = QHBoxLayout(self.adv_panel)
        adv.setContentsMargins(12, 10, 12, 10)
        adv.setSpacing(10)

        adv.addWidget(self._field_label("Source"))
        self.source_combo = _combo(["Any source"])
        for key in ("community_dns", "doh", "opengeo", "geoip",
                    "abuseipdb", "otx", "virustotal", "urlhaus",
                    "threatfox", "demo"):
            self.source_combo.addItem(key)
        self.source_combo.currentIndexChanged.connect(
            lambda: self.refresh(reset_page=True))
        adv.addWidget(self.source_combo)

        adv.addWidget(self._field_label("Tag"))
        self.tag_edit = QLineEdit()
        self.tag_edit.setPlaceholderText("e.g. phishing")
        self.tag_edit.setClearButtonEnabled(True)
        self.tag_edit.returnPressed.connect(lambda: self.refresh(reset_page=True))
        adv.addWidget(self.tag_edit, 1)

        adv.addWidget(self._field_label("Min risk"))
        self.risk_slider = QSlider(Qt.Orientation.Horizontal)
        self.risk_slider.setRange(0, 100)
        self.risk_slider.setValue(0)
        self.risk_slider.setFixedWidth(130)
        self.risk_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.risk_slider.setTickInterval(25)
        self.risk_slider.valueChanged.connect(self._on_risk_changed)
        adv.addWidget(self.risk_slider)
        self.risk_val = QLabel("Any")
        self.risk_val.setStyleSheet(
            "font-size: 11px; font-weight: 800; color: #DC2626;")
        adv.addWidget(self.risk_val)

        adv.addWidget(self._field_label("Last seen"))
        self.days_combo = _combo(
            ["Any time", "Last 24 hours", "Last 7 days", "Last 30 days"])
        self.days_combo.currentIndexChanged.connect(
            lambda: self.refresh(reset_page=True))
        adv.addWidget(self.days_combo)

        btn_reset = GhostButton("Reset", "refresh")
        btn_reset.clicked.connect(self._reset_filters)
        adv.addWidget(btn_reset)
        self.adv_panel.hide()
        bar.layout().addWidget(self.adv_panel)

        # ---- main action row ---------------------------------------------
        row2 = QHBoxLayout()
        btn_import = GhostButton("Import CSV", "upload")
        btn_import.clicked.connect(self._import_csv)
        row2.addWidget(btn_import)
        btn_export = GhostButton("Export CSV", "download")
        btn_export.clicked.connect(self._export_csv)
        row2.addWidget(btn_export)
        btn_json = GhostButton("Export JSON", "download")
        btn_json.clicked.connect(self._export_json)
        row2.addWidget(btn_json)
        self.lbl_filtered = label("", "Muted", wordwrap=False)
        self.lbl_filtered.setStyleSheet("font-size: 11.5px; color: #64748B;")
        row2.addWidget(self.lbl_filtered)
        row2.addStretch(1)
        self.btn_remove_filtered = DangerButton("Remove all filtered", "trash")
        self.btn_remove_filtered.setToolTip(
            "Delete EVERY indicator matching the current filters")
        self.btn_remove_filtered.clicked.connect(self._remove_all_filtered)
        row2.addWidget(self.btn_remove_filtered)
        btn_add = PrimaryButton("Add indicator", "plus")
        btn_add.clicked.connect(self._add_indicator)
        row2.addWidget(btn_add)
        bar.layout().addLayout(row2)
        self.body_lay.addWidget(bar)

        # ---- bulk selection bar ------------------------------------------
        self.bulk_bar = QFrame()
        self.bulk_bar.setObjectName("BulkBar")
        self.bulk_bar.setStyleSheet(
            "QFrame#BulkBar { background: #FEF2F2; border: 1px solid #FECACA;"
            " border-radius: 10px; }")
        bl = QHBoxLayout(self.bulk_bar)
        bl.setContentsMargins(12, 8, 12, 8)
        bl.setSpacing(8)
        self.bulk_lbl = QLabel("No selection")
        self.bulk_lbl.setStyleSheet(
            "font-size: 12px; font-weight: 800; color: #B91C1C;"
            "background: transparent;")
        bl.addWidget(self.bulk_lbl)
        bl.addStretch(1)
        self.btn_bulk_remove = DangerButton("Remove selected", "trash")
        self.btn_bulk_remove.clicked.connect(self._remove_selected)
        bl.addWidget(self.btn_bulk_remove)
        self.btn_bulk_rescan = GhostButton("Re-scan selected", "refresh")
        self.btn_bulk_rescan.clicked.connect(self._rescan_selected)
        bl.addWidget(self.btn_bulk_rescan)
        self.btn_bulk_tag = GhostButton("Tag selected", "edit")
        self.btn_bulk_tag.clicked.connect(self._tag_selected)
        bl.addWidget(self.btn_bulk_tag)
        self.btn_bulk_export = GhostButton("Export selected (CSV)", "download")
        self.btn_bulk_export.clicked.connect(self._export_selected)
        bl.addWidget(self.btn_bulk_export)
        self.btn_bulk_clear = GhostButton("Clear selection", "x")
        self.btn_bulk_clear.clicked.connect(self._clear_selection)
        bl.addWidget(self.btn_bulk_clear)
        self.bulk_bar.hide()
        self.body_lay.addWidget(self.bulk_bar)

        # table -------------------------------------------------------------
        card = Card()
        self.table = DataTable(
            ["Indicator", "Type", "Severity", "Risk", "Confidence",
             "Country", "ASN", "Last seen"],
            multi_select=True,
        )
        self.table.row_double.connect(self._open_detail)
        self.table.row_action.connect(self._remove_one)
        self.table.selection_changed.connect(self._on_selection_changed)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col, width in ((1, 74), (2, 92), (3, 80), (4, 100),
                           (5, 84), (6, 96), (7, 110)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(col, width)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(8, 76)
        card.layout().addWidget(self.table, 1)
        self.body_lay.addWidget(card, 1)

        # pagination strip ----------------------------------------------------
        pager = QWidget()
        pl = QHBoxLayout(pager)
        pl.setContentsMargins(0, 0, 0, 0)
        self.page_lbl = label("", "Muted")
        pl.addWidget(self.page_lbl)
        pl.addStretch(1)
        btn_select_page = GhostButton("Select page", "check")
        btn_select_page.clicked.connect(self._select_page)
        pl.addWidget(btn_select_page)
        self.btn_prev = GhostButton("Previous", "chevron-left")
        self.btn_prev.clicked.connect(self._prev_page)
        pl.addWidget(self.btn_prev)
        self.btn_next = GhostButton("Next", "chevron-right")
        self.btn_next.clicked.connect(self._next_page)
        pl.addWidget(self.btn_next)
        self.body_lay.addWidget(pager)
        self._page = 0

    # ----------------------------------------------------------- helpers
    @staticmethod
    def _field_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "font-size: 10.5px; font-weight: 800; color: #64748B;"
            "background: transparent;")
        return lbl

    def _current_filters(self) -> dict:
        return dict(
            query=self.search.text().strip(),
            type_=TYPE_MAP[self.type_combo.currentIndex()],
            severity=SEV_MAP[self.sev_combo.currentIndex()],
            source=("" if self.source_combo.currentIndex() == 0
                    else self.source_combo.currentText()),
            tag=self.tag_edit.text().strip(),
            min_risk=self.risk_slider.value(),
            days=DAYS_MAP[self.days_combo.currentIndex()],
        )

    # -------------------------------------------------------------- data
    def refresh(self, reset_page: bool = False) -> None:
        if reset_page:
            self._page = 0
        hub = ServiceHub.get()
        f = self._current_filters()
        order = ORDER_MAP[self.order_combo.currentIndex()]

        inds = hub.repo.search_indicators(
            limit=PAGE_SIZE, offset=self._page * PAGE_SIZE, order=order, **f)
        rows = []
        for ind in inds:
            rows.append([
                ind["value"],
                ind["type"].upper(),
                ind["severity"].upper(),
                f"{ind['risk_score']}/100",
                f"{round(ind['confidence'] * 100)}%",
                ind.get("country") or "—",
                ind.get("asn") or "—",
                relative_time(ind.get("last_seen")),
            ])
        self.table.set_rows(
            rows, inds,
            actions=[("trash", "Remove this indicator")])

        total = hub.repo.count_indicators_matching(**f)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.page_lbl.setText(
            f"{total} indicators · page {self._page + 1} of {pages}")
        self.btn_prev.setEnabled(self._page > 0)
        self.btn_next.setEnabled(self._page + 1 < pages)
        self.btn_remove_filtered.setEnabled(total > 0)
        self.btn_remove_filtered.setText(
            f"Remove all filtered ({total})" if total else "Remove all filtered")
        self.maybe_demo_banner()

    def _prev_page(self) -> None:
        if self._page > 0:
            self._page -= 1
            self.refresh()

    def _next_page(self) -> None:
        self._page += 1
        self.refresh()

    def _select_page(self) -> None:
        self.table.select_all_rows()

    # ------------------------------------------------------ advanced ui
    def _toggle_advanced(self, checked: bool) -> None:
        self.adv_panel.setVisible(checked)
        self.btn_adv.setText("Hide advanced" if checked else "Advanced")

    def _on_risk_changed(self, v: int) -> None:
        self.risk_val.setText("Any" if v == 0 else f"≥ {v}")
        self.refresh(reset_page=True)

    def _reset_filters(self) -> None:
        self.search.clear()
        self.type_combo.setCurrentIndex(0)
        self.sev_combo.setCurrentIndex(0)
        self.order_combo.setCurrentIndex(0)
        self.source_combo.setCurrentIndex(0)
        self.tag_edit.clear()
        self.risk_slider.blockSignals(True)
        self.risk_slider.setValue(0)
        self.risk_slider.blockSignals(False)
        self.risk_val.setText("Any")
        self.days_combo.setCurrentIndex(0)
        self.refresh(reset_page=True)

    # ------------------------------------------------------- selection ui
    def _on_selection_changed(self, count: int) -> None:
        self.bulk_bar.setVisible(count > 0)
        if count:
            self.bulk_lbl.setText(f"{count} indicator(s) selected")
        self.page_lbl.setText(self.page_lbl.text())

    def _clear_selection(self) -> None:
        self.table.clear_selection()

    # ------------------------------------------------------------ actions
    def _open_detail(self, ind: dict) -> None:
        from ...ui.dialogs.indicator_detail import IndicatorDetailDialog

        IndicatorDetailDialog(self, ind["id"])

    def _add_indicator(self) -> None:
        from ...ui.dialogs.common import TextDialog

        dlg = TextDialog(self, "Add indicator (IP, domain, URL or hash)",
                         placeholder="e.g. 192.0.2.55")
        if not dlg.exec():
            return
        hub = ServiceHub.get()
        report = hub.engine.lookup(dlg.value())
        if report:
            self.refresh(reset_page=True)
            hub.events.publish(
                "lookup.completed",
                f"Indicator '{dlg.value()}' added and analyzed",
                severity="success")
        else:
            QMessageBox.warning(self, "Invalid indicator",
                                "The entered value is not a valid IP, domain, "
                                "URL or hash.")

    # ---- remove operations ---------------------------------------------
    def _remove_one(self, ind: dict) -> None:
        """Quick per-row remove (trash button / context menu)."""
        from ...ui.dialogs.common import ConfirmDialog

        value = ind.get("value", "this indicator")
        dlg = ConfirmDialog(
            self, "Remove indicator",
            f"Remove '{value}' from the intelligence database?\n"
            "Its findings and relationships are deleted too.",
            confirm_text="Remove")
        if not dlg.accepted():
            return
        hub = ServiceHub.get()
        hub.repo.delete_indicator(ind["id"])
        hub.events.publish("indicator.deleted",
                           f"Indicator '{value}' removed", severity="warning")
        self.refresh()

    def _remove_selected(self) -> None:
        from ...ui.dialogs.common import ConfirmDialog

        sel = self.table.selected_payloads()
        if not sel:
            return
        dlg = ConfirmDialog(
            self, "Remove selected indicators",
            f"Remove {len(sel)} selected indicator(s) and all of their "
            "findings and relationships?",
            confirm_text=f"Remove {len(sel)}")
        if not dlg.accepted():
            return
        hub = ServiceHub.get()
        removed = hub.repo.delete_indicators_batch([i["id"] for i in sel])
        hub.events.publish("indicators.bulk_deleted",
                           f"{removed} selected indicator(s) removed",
                           severity="warning")
        self.refresh()

    def _remove_all_filtered(self) -> None:
        from ...ui.dialogs.common import ConfirmDialog

        hub = ServiceHub.get()
        f = self._current_filters()
        total = hub.repo.count_indicators_matching(**f)
        if not total:
            QMessageBox.information(self, "Nothing to remove",
                                    "No indicators match the current filters.")
            return
        dlg = ConfirmDialog(
            self, "Remove all filtered indicators",
            f"This permanently deletes ALL {total} indicator(s) matching the "
            "current filters, including their findings and relationships.\n"
            "This cannot be undone.",
            confirm_text=f"Delete all {total}")
        if not dlg.accepted():
            return
        removed = hub.repo.delete_indicators_matching(**f)
        hub.events.publish("indicators.bulk_deleted",
                           f"{removed} filtered indicator(s) removed",
                           severity="critical")
        self.refresh(reset_page=True)

    # ---- advanced bulk actions -------------------------------------------
    def _rescan_selected(self) -> None:
        sel = self.table.selected_payloads()
        if not sel:
            return
        hub = ServiceHub.get()
        done = 0
        for ind in sel:
            try:
                if hub.engine.lookup(ind.get("value", "")):
                    done += 1
            except Exception:  # noqa: BLE001
                continue
        hub.events.publish("lookup.completed",
                           f"Re-scan finished — {done}/{len(sel)} indicator(s) "
                           "re-analyzed", severity="success")
        self.refresh()

    def _tag_selected(self) -> None:
        from ...ui.dialogs.common import TextDialog

        sel = self.table.selected_payloads()
        if not sel:
            return
        dlg = TextDialog(self, f"Add tag to {len(sel)} indicator(s)",
                         placeholder="e.g. apt-watchlist")
        if not dlg.exec():
            return
        hub = ServiceHub.get()
        tag = dlg.value()
        for ind in sel:
            hub.repo.add_tag(ind["id"], tag)
        hub.events.publish("lookup.completed",
                           f"Tag '{tag}' applied to {len(sel)} indicator(s)",
                           severity="success")
        self.refresh()

    def _export_selected(self) -> None:
        sel = self.table.selected_payloads()
        if not sel:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export selected indicators",
            "aegisx-selected-indicators.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            count = export_indicators_csv(Path(path), [i["id"] for i in sel])
            QMessageBox.information(
                self, "Export complete",
                f"{count} selected indicators written to {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Export failed", str(e))

    # ---- context menu ------------------------------------------------------
    def _context_menu(self, pos) -> None:
        menu = QMenu(self)
        sel = self.table.selected_payloads()
        row_at = self.table.rowAt(pos.y())
        payload = (self.table._payloads[row_at]
                   if 0 <= row_at < len(self.table._payloads) else None)
        if payload and payload not in sel:
            sel = [payload]

        if payload:
            act_open = QAction("Open details", self)
            act_open.triggered.connect(
                lambda: self._open_detail(payload))
            menu.addAction(act_open)
            act_copy = QAction("Copy value", self)
            act_copy.triggered.connect(
                lambda: self._copy_value(payload))
            menu.addAction(act_copy)
            act_scan = QAction("Re-analyze (re-scan providers)", self)
            act_scan.triggered.connect(
                lambda: self._rescan_one(payload))
            menu.addAction(act_scan)
            act_tag = QAction("Add tag…", self)
            act_tag.triggered.connect(lambda: self._tag_one(payload))
            menu.addAction(act_tag)
            menu.addSeparator()
        if sel:
            act_rem = QAction(f"Remove {len(sel)} indicator(s)…", self)
            act_rem.triggered.connect(self._remove_selected)
            menu.addAction(act_rem)
        if payload:
            act_del = QAction("Remove this indicator…", self)
            act_del.triggered.connect(
                lambda: self._remove_one(payload))
            menu.addAction(act_del)
        if menu.isEmpty():
            return
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _copy_value(self, ind: dict) -> None:
        from PySide6.QtWidgets import QApplication

        QApplication.clipboard().setText(ind.get("value", ""))

    def _rescan_one(self, ind: dict) -> None:
        hub = ServiceHub.get()
        ok = hub.engine.lookup(ind.get("value", ""))
        hub.events.publish("lookup.completed",
                           f"Re-analyzed '{ind.get('value', '')}'"
                           + ("" if ok else " (no providers available)"),
                           severity="success" if ok else "warning")
        self.refresh()

    def _tag_one(self, ind: dict) -> None:
        from ...ui.dialogs.common import TextDialog

        dlg = TextDialog(self, f"Add tag to '{ind.get('value', '')}'",
                         placeholder="e.g. apt-watchlist")
        if not dlg.exec():
            return
        hub = ServiceHub.get()
        hub.repo.add_tag(ind["id"], dlg.value())
        hub.events.publish("lookup.completed",
                           f"Tag '{dlg.value()}' added to '{ind.get('value', '')}'",
                           severity="success")
        self.refresh()

    # ---- import / export --------------------------------------------------
    def _import_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import indicators CSV", "",
                                              "CSV files (*.csv)")
        if not path:
            return
        try:
            count, errors = import_indicators_csv(Path(path))
            QMessageBox.information(
                self, "Import complete",
                f"Imported {count} indicators."
                + (f"\n{errors} rows skipped." if errors else ""))
            self.refresh(reset_page=True)
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Import failed", str(e))

    def _export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export indicators CSV",
                                              "aegisx-indicators.csv",
                                              "CSV files (*.csv)")
        if not path:
            return
        try:
            count = export_indicators_csv(Path(path))
            QMessageBox.information(self, "Export complete",
                                    f"{count} indicators written to {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Export failed", str(e))

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export indicators JSON",
                                              "aegisx-indicators.json",
                                              "JSON (*.json)")
        if not path:
            return
        hub = ServiceHub.get()
        f = self._current_filters()
        inds = hub.repo.search_indicators(limit=5000, **f)
        Path(path).write_text(json.dumps(inds, indent=2, default=str),
                              encoding="utf-8")
        QMessageBox.information(self, "Export complete",
                                f"{len(inds)} indicators written to {path}")
