"""
AegisX — Settings page.

Provider credentials, analysis behaviour, data & cache management,
appearance and logging — all backed by real, persisted settings.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ..components import (
    Badge,
    Banner,
    Card,
    DangerButton,
    DangerButton as _DB,
    GhostButton,
    KVWidget,
    PrimaryButton,
    label,
)
from ..dialogs import ProviderDialog
from .base_page import PageBase


class SettingsPage(PageBase):
    title = "Settings"
    subtitle = "Platform configuration — providers, behaviour, data and appearance."
    page_key = "settings"

    def build(self) -> None:
        self.maybe_demo_banner()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        scroll.setWidget(host)
        self.body_lay.addWidget(scroll, 1)

        # ------------------------------------------------------ providers
        card_p = Card()
        card_p.layout().addWidget(label("Intelligence Providers", "H2"))
        card_p.layout().addWidget(label(
            "Keyless community sources (Spamhaus DBL/ZEN, Tor exits, DNS over "
            "HTTPS, crt.sh, OpenGeo) query live intelligence without any key. "
            "API-key feeds stack on top — abuse.ch sources (URLhaus/ThreatFox) "
            "share one free Auth-Key from auth.abuse.ch.", "Muted"))
        self.providers_area = QWidget()
        self.providers_lay = QVBoxLayout(self.providers_area)
        self.providers_lay.setContentsMargins(0, 0, 0, 0)
        self.providers_lay.setSpacing(8)
        card_p.layout().addWidget(self.providers_area)
        lay.addWidget(card_p)

        # ------------------------------------------------------ analysis
        card_a = Card()
        card_a.layout().addWidget(label("Analysis Behaviour", "H2"))
        row_demo = QHBoxLayout()
        lbl_demo = label("Demonstration mode", "H3")
        lbl_demo.setToolTip("Show clearly-labelled sample data instead of querying providers")
        row_demo.addWidget(lbl_demo)
        row_demo.addStretch(1)
        self.chk_demo = QCheckBox()
        self.chk_demo.setChecked(self.hub().demo_mode)
        self.chk_demo.setEnabled(False)
        self.chk_demo.setToolTip("Sample data is disabled; AegisX uses real provider results only")
        self.chk_demo.toggled.connect(self._toggle_demo)
        row_demo.addWidget(self.chk_demo)
        card_a.layout().addLayout(row_demo)

        row_analyst = QHBoxLayout()
        row_analyst.addWidget(label("Analyst name", "H3"))
        row_analyst.addStretch(1)
        self.analyst_edit = _QLineEdit = None
        from PySide6.QtWidgets import QLineEdit

        self.analyst_edit = QLineEdit(self.hub().settings.get("analyst_name"))
        self.analyst_edit.setFixedWidth(220)
        self.analyst_edit.editingFinished.connect(
            lambda: self.hub().settings.set("analyst_name", self.analyst_edit.text().strip()))
        row_analyst.addWidget(self.analyst_edit)
        card_a.layout().addLayout(row_analyst)
        lay.addWidget(card_a)

        # ------------------------------------------------------ data & cache
        card_d = Card()
        card_d.layout().addWidget(label("Data & Cache", "H2"))
        self.data_kv = KVWidget()
        lay_d = self.data_kv.layout()
        card_d.layout().addWidget(self.data_kv)
        row_cache = QHBoxLayout()
        btn_clear = GhostButton("Clear response cache", "trash")
        btn_clear.clicked.connect(self._clear_cache)
        row_cache.addWidget(btn_clear)
        btn_open_reports = GhostButton("Open reports folder", "folder")
        btn_open_reports.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(_reports_dir()))))
        row_cache.addWidget(btn_open_reports)
        row_cache.addStretch(1)
        card_d.layout().addLayout(row_cache)

        row_export = QHBoxLayout()
        btn_export = GhostButton("Export all data (JSON)", "download")
        btn_export.clicked.connect(self._export_all)
        row_export.addWidget(btn_export)
        row_export.addStretch(1)
        card_d.layout().addLayout(row_export)

        row_wipe = QHBoxLayout()
        btn_wipe = DangerButton("Wipe database…", "alert")
        btn_wipe.clicked.connect(self._wipe_db)
        row_wipe.addWidget(btn_wipe)
        row_wipe.addStretch(1)
        card_d.layout().addLayout(row_wipe)
        lay.addWidget(card_d)

        # ------------------------------------------------------ logging
        card_l = Card()
        card_l.layout().addWidget(label("Logging", "H2"))
        row_log = QHBoxLayout()
        row_log.addWidget(label("Log level", "H3"))
        row_log.addStretch(1)
        self.log_combo = QComboBox()
        self.log_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_combo.setCurrentText(self.hub().settings.get("log_level") or "INFO")
        self.log_combo.currentTextChanged.connect(self._set_log_level)
        row_log.addWidget(self.log_combo)
        card_l.layout().addLayout(row_log)
        btn_logs = GhostButton("Open log folder", "folder")
        btn_logs.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(_logs_dir()))))
        card_l.layout().addWidget(btn_logs)
        lay.addWidget(card_l)

        self.db_path_lbl = Banner("", "info")

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        hub = self.hub()
        while self.providers_lay.count():
            item = self.providers_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for name, p in hub.engine.providers.items():
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(2, 4, 2, 4)
            col = QVBoxLayout()
            col.addWidget(label(p.display_name, "H3"))
            col.addWidget(label(p.description[:90] + ("…" if len(p.description) > 90 else ""), "Muted"))
            rl.addLayout(col, 1)
            configured = p.is_configured()
            if not p.requires_key:
                badge = Badge("KEYLESS · LIVE", "info" if configured else "medium")
            elif configured:
                badge = Badge("CONFIGURED", "success")
            else:
                badge = Badge("FREE KEY OPTIONAL", "medium")
            rl.addWidget(badge)
            btn = PrimaryButton("Configure", "settings")
            btn.clicked.connect(lambda _=False, prov=p: self._configure(prov))
            rl.addWidget(btn)
            self.providers_lay.addWidget(row)

        self.data_kv.set_items([
            ("Database", str(hub.repo.db_path)),
            ("Reports folder", str(_reports_dir())),
            ("Config folder", str(_config_dir())),
            ("Key storage", hub.keystore.backend_description()),
            ("Cache entries", str(hub.repo.cache_stats()["entries"])),
        ], mono_keys=("Database", "Reports folder", "Config folder"))
        self.maybe_demo_banner()

    # ---------------------------------------------------------------- actions
    def _configure(self, provider) -> None:
        ProviderDialog(self, provider, on_saved=lambda _n: self.refresh()).exec()
        self.refresh()

    def _toggle_demo(self, checked: bool) -> None:
        self.hub().set_demo_mode(checked)
        win = self.window()
        if hasattr(win, "update_mode_status"):
            win.update_mode_status()
        self.refresh()

    def _set_log_level(self, level: str) -> None:
        import logging

        self.hub().settings.set("log_level", level)
        logging.getLogger().setLevel(getattr(logging, level, logging.INFO))

    def _clear_cache(self) -> None:
        n = self.hub().repo.cache_clear()
        self.hub().events.publish("cache.cleared", f"Cache cleared ({n} entries)", severity="info")
        self.refresh()

    def _export_all(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export all data",
                                              "aegisx-export.json", "JSON (*.json)")
        if not path:
            return
        import json

        data = self.hub().repo.export_all()
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        QMessageBox.information(self, "Export complete", f"All data exported to {path}")

    def _wipe_db(self) -> None:
        from ..dialogs.common import ConfirmDialog

        dialog = ConfirmDialog(
            self, "Wipe entire database",
            "This permanently deletes every indicator, finding, relationship, campaign, "
            "investigation and report record. Configuration and API keys are kept. "
            "This cannot be undone.",
            confirm_text="Wipe everything")
        if dialog.result() != 1:
            return
        self.hub().repo.wipe_all()
        self.hub().events.publish("db.wiped", "Database wiped by analyst", severity="critical")
        self.refresh()


def _reports_dir():
    from ...utils.paths import reports_dir

    return reports_dir()


def _config_dir():
    from ...utils.paths import config_dir

    return config_dir()


def _logs_dir():
    from ...utils.paths import logs_dir

    return logs_dir()
