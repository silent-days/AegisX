"""AegisX — provider API key configuration dialog with live connectivity test."""

from __future__ import annotations

import requests

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ...providers import ProviderAdapter, ProviderError, ProviderNotConfigured
from ...styles import theme
from ..components import (
    Badge,
    GhostButton,
    PrimaryButton,
    Spinner,
    label,
)
from ..icons import icon


class ProviderDialog(QDialog):
    """Configure an intelligence provider: API key + connectivity test."""

    def __init__(self, parent: QWidget | None, provider: ProviderAdapter,
                 on_saved=None) -> None:
        super().__init__(parent)
        self.provider = provider
        self.on_saved = on_saved
        self.setWindowTitle(f"Configure {provider.display_name}")
        self.setModal(True)
        self.setFixedWidth(560)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 20)
        lay.setSpacing(12)

        head = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.addWidget(label(provider.display_name, "H2"))
        desc = QLabel(provider.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #64748B; font-size: 12px;")
        title_col.addWidget(desc)
        head.addLayout(title_col, 1)
        head.addStretch(1)
        self.status_badge = Badge("FREE KEY OPTIONAL" if provider.requires_key else "READY",
                                  "info" if not provider.requires_key else "medium")
        head.addWidget(self.status_badge)
        lay.addLayout(head)

        caps = QLabel(" · ".join(provider.capabilities))
        caps.setStyleSheet(f"color: {theme.COLORS['text_muted']}; font-size: 11px;")
        lay.addWidget(caps)

        if provider.requires_key:
            key_row = QHBoxLayout()
            self.key_edit = QLineEdit()
            self.key_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.key_edit.setPlaceholderText(f"{provider.display_name} API key")
            key_row.addWidget(self.key_edit, 1)
            self.btn_reveal = GhostButton("Show")
            self.btn_reveal.setCheckable(True)
            self.btn_reveal.toggled.connect(self._toggle_reveal)
            key_row.addWidget(self.btn_reveal)
            lay.addLayout(key_row)
            current = provider.api_key()
            if current:
                self.key_edit.setText(current)
            where = getattr(provider, "key_url", "") or provider.docs_url
            hint = QLabel(
                f'Get a free key: <a href="{where}">{where}</a>')
            hint.setOpenExternalLinks(True)
            hint.setStyleSheet(f"color: {theme.COLORS['primary']}; font-size: 11.5px;")
            lay.addWidget(hint)
        else:
            self.key_edit = None
            note = QLabel(
                f"This provider does not require an API key. Rate limit: one request every "
                f"{provider.min_interval:.0f}s · cache TTL {provider.default_ttl // 3600}h."
                if provider.min_interval >= 1
                else "This provider does not require an API key."
            )
            note.setWordWrap(True)
            note.setStyleSheet("color: #64748B; font-size: 12px;")
            lay.addWidget(note)

        if provider.name == "geoip":
            from PySide6.QtWidgets import QLineEdit as _LE

            self.db_edit = _LE(self.provider.db_path())
            self.db_edit.setPlaceholderText("/path/to/GeoLite2-City.mmdb")
            lay.addWidget(label("GeoLite2-City database path:", "H3"))
            lay.addWidget(self.db_edit)

        # test result strip
        self.result = QFrame()
        rl = QHBoxLayout(self.result)
        rl.setContentsMargins(10, 8, 10, 8)
        self.result_icon = QLabel()
        self.result_text = QLabel("Ready to test.")
        self.result_text.setStyleSheet("font-size: 12px; color: #64748B;")
        self.spinner = Spinner(18)
        self.spinner.hide()
        rl.addWidget(self.result_icon)
        rl.addWidget(self.result_text, 1)
        rl.addWidget(self.spinner)
        self.result.setStyleSheet(
            f"background: {theme.COLORS['surface_alt']}; border-radius: 9px; border: 1px solid {theme.COLORS['divider']};"
        )
        lay.addWidget(self.result)

        # actions
        row = QHBoxLayout()
        self.btn_test = PrimaryButton("Test connection", "refresh")
        self.btn_test.clicked.connect(self._test)
        row.addWidget(self.btn_test)
        row.addStretch(1)
        btn_cancel = GhostButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        row.addWidget(btn_cancel)
        if provider.requires_key:
            btn_clear = GhostButton("Remove key")
            btn_clear.clicked.connect(self._clear)
            row.addWidget(btn_clear)
        btn_save = PrimaryButton("Save")
        btn_save.clicked.connect(self._save)
        row.addWidget(btn_save)
        lay.addLayout(row)

    # ------------------------------------------------------------------ slots
    def _toggle_reveal(self, shown: bool) -> None:
        if self.key_edit:
            self.key_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password
            )

    def _set_result(self, ok: bool, text: str) -> None:
        self.spinner.hide()
        ic = icon("check" if ok else "alert",
                  theme.COLORS["success"] if ok else theme.COLORS["critical"], 15)
        self.result_icon.show()
        self.result_icon.setPixmap(ic.pixmap(15, 15))
        self.result_text.setText(text)
        self.result_text.setStyleSheet(
            f"font-size: 12px; color: {theme.COLORS['success'] if ok else theme.COLORS['critical']}; font-weight: 600;"
        )

    def _test(self) -> None:
        self.btn_test.setEnabled(False)
        self.result_icon.hide()
        self.spinner.show()
        self.result_text.setText("Contacting provider…")
        self.repaint()
        key = self.key_edit.text().strip() if self.key_edit else None
        if self.provider.requires_key and key:
            self.provider.keystore.set_key(self.provider.name, key)  # temp enable test
        if self.provider.name == "geoip" and hasattr(self, "db_edit"):
            try:
                from ...core.services import ServiceHub

                ServiceHub.get().repo.set_setting("geoip_db_path", self.db_edit.text().strip())
            except Exception:  # noqa: BLE001
                pass
        try:
            msg = self.provider.test_connection()
            self._set_result(True, msg)
        except ProviderNotConfigured as e:
            self._set_result(False, str(e))
        except ProviderError as e:
            self._set_result(False, str(e))
        except Exception as e:  # noqa: BLE001
            self._set_result(False, f"Unexpected error: {e}")
        finally:
            self.btn_test.setEnabled(True)

    def _clear(self) -> None:
        if self.key_edit is not None:
            self.key_edit.clear()
            self.provider.keystore.delete_key(self.provider.name)
            self.status_badge.setText("NOT CONFIGURED")
            self._set_result(False, "API key removed — provider disabled until reconfigured.")

    def _save(self) -> None:
        if self.key_edit is not None:
            self.provider.keystore.set_key(self.provider.name, self.key_edit.text().strip())
        if self.provider.name == "geoip" and hasattr(self, "db_edit"):
            from ...core.services import ServiceHub

            ServiceHub.get().repo.set_setting("geoip_db_path", self.db_edit.text().strip())
        self.accept()
        if self.on_saved:
            self.on_saved(self.provider.name)
