"""
AegisX — Intelligence Sources page.

Provider management: configuration state, capabilities, connectivity tests,
rate limits, cache statistics and maintenance actions.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from ...workers import TaskManager
from ..components import (
    Badge,
    Banner,
    Card,
    GhostButton,
    PrimaryButton,
    Spinner,
    label,
    relative_time,
)
from ..dialogs import ProviderDialog
from .base_page import PageBase


class SourcesPage(PageBase):
    title = "Intelligence Sources"
    subtitle = "Configure and monitor the intelligence providers feeding AegisX."
    page_key = "sources"

    def build(self) -> None:
        self.maybe_demo_banner()

        top = QWidget()
        tl = QHBoxLayout(top)
        tl.setContentsMargins(0, 0, 0, 0)
        self.summary_lbl = label("", "Subtitle")
        tl.addWidget(self.summary_lbl, 1)
        btn_test_all = GhostButton("Test all configured", "refresh")
        btn_test_all.clicked.connect(self._test_all)
        tl.addWidget(btn_test_all)
        btn_clear_cache = GhostButton("Clear cache", "trash")
        btn_clear_cache.clicked.connect(self._clear_cache)
        tl.addWidget(btn_clear_cache)
        self.body_lay.addWidget(top)

        self.grid_host = QWidget()
        self.grid = QGridLayout(self.grid_host)
        self.grid.setSpacing(14)
        self.body_lay.addWidget(self.grid_host, 1)

        self.key_backend = Banner("", "info")
        self.body_lay.addWidget(self.key_backend)

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        hub = self.hub()
        states = {s["name"]: s for s in hub.repo.source_states()}
        cache = hub.repo.cache_stats()
        keyless = [p for p in hub.engine.providers.values()
                   if p.is_configured() and not p.requires_key]
        configured = sum(1 for p in hub.engine.providers.values()
                         if p.is_configured() and p.requires_key)
        key_required = sum(1 for p in hub.engine.providers.values() if p.requires_key)
        self.summary_lbl.setText(
            f"{len(keyless)} keyless community sources live (zero setup) · "
            f"{configured}/{key_required} key-based providers configured · "
            f"cache: {cache['entries']} entries ({cache['bytes'] / 1024:.0f} KB)")

        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for i, (name, p) in enumerate(hub.engine.providers.items()):
            self.grid.addWidget(self._provider_card(p, states.get(p.name, {})), i // 2, i % 2)
        for c in range(2):
            self.grid.setColumnStretch(c, 1)
        self.grid.setRowStretch((len(hub.engine.providers) + 1) // 2, 1)

        self.key_backend.set_text(
            f"Credential storage: {hub.keystore.backend_description()}. "
            "Keys never leave this machine and are sent only to the provider you choose.")
        self.maybe_demo_banner()

    def _provider_card(self, p, st: dict) -> QWidget:
        card = Card()
        head = QHBoxLayout()
        col = QVBoxLayout()
        col.addWidget(label(p.display_name, "H2"))
        desc = label(p.description, "Muted")
        col.addWidget(desc)
        head.addLayout(col, 1)

        configured = p.is_configured()
        state = st.get("state", "unknown")
        if p.requires_key and not configured:
            # Missing free key is a setup hint — never a red error state.
            badge = Badge("FREE KEY OPTIONAL", "medium")
        elif state == "online":
            badge = Badge("ONLINE", "success")
        elif state == "error":
            badge = Badge("ERROR", "critical")
        else:
            badge = Badge("READY", "info")
        head.addWidget(badge)
        card.layout().addLayout(head)

        caps_row = QHBoxLayout()
        for cap in p.capabilities:
            caps_row.addWidget(Badge(cap, "info"))
        caps_row.addStretch(1)
        card.layout().addLayout(caps_row)

        kv = label(
            f"Rate limit: {p.min_interval:.1f}s between requests · cache TTL "
            f"{p.default_ttl // 3600}h · requests: {st.get('requests', 0)} · "
            f"failures: {st.get('failures', 0)}"
            + (f" · last success: {relative_time(st.get('last_success'))}" if st.get("last_success") else ""),
            "Muted")
        card.layout().addWidget(kv)
        if st.get("last_error") and not (p.requires_key and not configured):
            # Stale "no key yet" messages are hidden for unconfigured sources.
            err = label(f"Last error: {st['last_error'][:140]}", "Muted")
            err.setStyleSheet(f"color: {theme_critical()}; font-size: 11px;")
            card.layout().addWidget(err)

        row = QHBoxLayout()
        btn_docs = GhostButton("Docs", "external")
        btn_docs.clicked.connect(lambda _=False, url=p.docs_url: QDesktopServices.openUrl(QUrl(url)))
        row.addWidget(btn_docs)
        btn_test = GhostButton("Test", "refresh")
        btn_test.clicked.connect(lambda _=False, prov=p, card=card: self._test_one(prov, card))
        row.addWidget(btn_test)
        row.addStretch(1)
        btn_cfg = PrimaryButton("Configure", "settings")
        btn_cfg.clicked.connect(lambda _=False, prov=p: self._configure(prov))
        row.addWidget(btn_cfg)
        card.layout().addLayout(row)
        return card

    # ------------------------------------------------------------- actions
    def _configure(self, provider) -> None:
        dlg = ProviderDialog(self, provider, on_saved=lambda _name: self.refresh())
        if dlg.exec():
            self.hub().events.publish("source.configured",
                                      f"{provider.display_name} configuration updated",
                                      severity="success")
            self.refresh()

    def _test_one(self, provider, card: QWidget | None = None) -> None:
        hub = self.hub()
        TaskManager.get().submit(
            provider.test_connection,
            description=f"test-{provider.name}",
            on_done=lambda msg: self._test_done(provider, msg, True),
            on_error=lambda err: self._test_done(provider, err, False),
        )

    def _test_done(self, provider, msg: str, ok: bool) -> None:
        hub = self.hub()
        hub.repo.set_source_state(provider.name, "online" if ok else "error",
                                  error="" if ok else msg[:300])
        hub.events.publish(
            "source.tested",
            f"{provider.display_name}: {msg[:110]}",
            severity="success" if ok else "warning",
        )
        self.refresh()

    def _test_all(self) -> None:
        hub = self.hub()
        for p in hub.engine.providers.values():
            if p.is_configured():
                if p.name == "geoip":
                    continue  # auto-tested once the GeoLite2 path is saved
                self._test_one(p)
            elif "abuse.ch" in (p.key_url or ""):
                # Keyless-safe probes run for abuse.ch feeds too: they prove
                # reachability even while the free Auth-Key is pending.
                self._test_one(p)

    def _clear_cache(self) -> None:
        hub = self.hub()
        n = hub.repo.cache_clear()
        hub.events.publish("cache.cleared", f"Response cache cleared ({n} entries)",
                           severity="info")
        self.refresh()


def theme_critical() -> str:
    from ...styles import theme

    return theme.COLORS["critical"]
