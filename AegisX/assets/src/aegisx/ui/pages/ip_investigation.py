"""
AegisX — IP Investigation page.

Full analysis workspace for IP indicators: async multi-provider lookup,
evidence-based verdict with animated risk gauge, per-source finding cards,
GeoIP mini-map, MITRE ATT&CK associations and investigation actions.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...providers.base import ProviderError, ProviderNotConfigured
from ...styles import theme
from ...utils.validators import normalize_ip
from ...visualization.threat_map import ThreatMapWidget
from ...workers import TaskManager
from ..components import (
    Badge,
    Banner,
    Card,
    DangerButton,
    EmptyState,
    GaugeWidget,
    GhostButton,
    KVWidget,
    PrimaryButton,
    Spinner,
    label,
    relative_time,
)
from .base_page import PageBase


class IPInvestigationPage(PageBase):
    title = "IP Investigation"
    subtitle = "Deep reputation analysis of suspicious IP addresses across all configured sources."
    page_key = "ip_investigation"

    def build(self) -> None:
        self.maybe_demo_banner()

        # ---------------------------------------------------------- search bar
        search_card = Card()
        sl = QHBoxLayout()
        sl.setSpacing(10)
        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter an IP address — e.g. 192.0.2.44")
        self.input.setFixedHeight(42)
        self.input.textChanged.connect(self._validate_input)
        self.input.returnPressed.connect(self.run_lookup)
        sl.addWidget(self.input, 1)
        self.btn_lookup = PrimaryButton("Investigate", "search")
        self.btn_lookup.setFixedHeight(42)
        self.btn_lookup.clicked.connect(self.run_lookup)
        sl.addWidget(self.btn_lookup)
        self.btn_refresh = GhostButton("Force refresh", "refresh")
        self.btn_refresh.setFixedHeight(42)
        self.btn_refresh.clicked.connect(lambda: self.run_lookup(force=True))
        sl.addWidget(self.btn_refresh)
        search_card.layout().addLayout(sl)
        self.error_lbl = label("", "Muted")
        self.error_lbl.setStyleSheet("color: #DC2626; font-size: 12px;")
        search_card.layout().addWidget(self.error_lbl)
        self.body_lay.addWidget(search_card)

        # -------------------------------------------------------- progress row
        self.progress_row = QWidget()
        pl = QHBoxLayout(self.progress_row)
        pl.setContentsMargins(4, 0, 4, 0)
        pl.setSpacing(10)
        self.spinner = Spinner(22)
        self.spinner.hide()
        pl.addWidget(self.spinner)
        self.progress_lbl = label("", "Subtitle")
        pl.addWidget(self.progress_lbl, 1)
        self.progress_row.hide()
        self.body_lay.addWidget(self.progress_row)

        # ------------------------------------------------------------- results
        self.results_scroll = QScrollArea()
        self.results_scroll.setWidgetResizable(True)
        self.results_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.results_area = QWidget()
        rl = QVBoxLayout(self.results_area)
        rl.setContentsMargins(0, 0, 6, 0)
        rl.setSpacing(14)
        self.results_scroll.setWidget(self.results_area)

        # verdict row: gauge + factors
        verdict_row = QWidget()
        vr = QHBoxLayout(verdict_row)
        vr.setContentsMargins(0, 0, 0, 0)
        vr.setSpacing(14)
        card_gauge = Card()
        card_gauge.layout().addWidget(label("Risk Verdict", "H3"))
        self.gauge = GaugeWidget()
        self.gauge.setMinimumHeight(190)
        card_gauge.layout().addWidget(self.gauge, 1)
        vr.addWidget(card_gauge, 1)

        card_factors = Card()
        card_factors.layout().addWidget(label("Evidence Factors", "H3"))
        self.factors_area = QWidget()
        self.factors_lay = QVBoxLayout(self.factors_area)
        self.factors_lay.setContentsMargins(0, 0, 0, 0)
        self.factors_lay.setSpacing(6)
        card_factors.layout().addWidget(self.factors_area, 1)
        vr.addWidget(card_factors, 2)
        rl.addWidget(verdict_row)

        # context row: geo map + context details
        ctx_row = QWidget()
        cr = QHBoxLayout(ctx_row)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(14)
        card_map = Card()
        card_map.layout().addWidget(label("Approximate Geolocation", "H3"))
        self.map = ThreatMapWidget(compact=True)
        card_map.layout().addWidget(self.map, 1)
        cr.addWidget(card_map, 3)

        card_ctx = Card()
        card_ctx.layout().addWidget(label("Network Context", "H3"))
        self.context = KVWidget()
        card_ctx.layout().addWidget(self.context, 1)
        cr.addWidget(card_ctx, 2)
        rl.addWidget(ctx_row)

        # MITRE row
        card_mitre = Card()
        card_mitre.layout().addWidget(label("MITRE ATT&CK Associations", "H3"))
        self.mitre_area = QWidget()
        ml = QHBoxLayout(self.mitre_area)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(8)
        card_mitre.layout().addWidget(self.mitre_area)
        rl.addWidget(card_mitre)

        # source findings
        card_sources = Card()
        card_sources.layout().addWidget(label("Source Findings", "H3"))
        self.sources_area = QWidget()
        self.sources_lay = QVBoxLayout(self.sources_area)
        self.sources_lay.setContentsMargins(0, 0, 0, 0)
        self.sources_lay.setSpacing(10)
        card_sources.layout().addWidget(self.sources_area, 1)
        rl.addWidget(card_sources)

        # actions
        actions = QWidget()
        al = QHBoxLayout(actions)
        al.setContentsMargins(0, 0, 0, 0)
        al.setSpacing(10)
        self.btn_add_inv = PrimaryButton("Add to investigation", "plus")
        self.btn_add_inv.clicked.connect(self._add_to_investigation)
        al.addWidget(self.btn_add_inv)
        self.btn_copy = GhostButton("Copy JSON", "file")
        self.btn_copy.clicked.connect(self._copy_json)
        al.addWidget(self.btn_copy)
        al.addStretch(1)
        self.cache_lbl = label("", "Muted")
        al.addWidget(self.cache_lbl)
        rl.addWidget(actions)

        self.empty = EmptyState(
            "Run an IP investigation",
            "Enter any IPv4/IPv6 address above — AegisX queries every configured "
            "intelligence source, scores the evidence and maps the infrastructure.",
            icon_name="target",
        )
        rl.addWidget(self.empty)

        self.body_lay.addWidget(self.results_scroll, 1)
        self.results_scroll.hide()
        self._last_report: dict | None = None

    # ---------------------------------------------------------------- input
    def set_input(self, value: str) -> None:
        self.input.setText(value)

    def _validate_input(self) -> None:
        text = self.input.text().strip()
        if not text:
            self.error_lbl.setText("")
            return
        norm = normalize_ip(text)
        self.error_lbl.setText("" if norm else "Not a valid IP address.")

    # ---------------------------------------------------------------- lookup
    def run_lookup(self, force: bool = False) -> None:
        value = self.input.text().strip()
        if not value:
            self.error_lbl.setText("Enter an IP address first.")
            return
        norm = normalize_ip(value)
        if not norm:
            self.error_lbl.setText("Not a valid IP address.")
            return
        self.error_lbl.setText("")
        self.btn_lookup.setEnabled(False)
        self.results_scroll.hide()
        self.empty.hide()
        self.progress_row.show()
        self.spinner.start()
        self.progress_lbl.setText("Normalizing indicator…")

        hub = self.hub()
        TaskManager.get().submit(
            hub.engine.lookup, value, force_refresh=force,
            description=f"ip-lookup {value}",
            on_done=self._on_result,
            on_error=self._on_error,
        )

    def _progress(self, msg, _pct=None) -> None:
        self.progress_lbl.setText(msg)

    def _on_result(self, report: dict | None) -> None:
        self.btn_lookup.setEnabled(True)
        self.spinner.stop()
        self.progress_row.hide()
        if not report:
            self.error_lbl.setText("Analysis returned no report.")
            return
        self._last_report = report
        self._render(report)
        self.results_scroll.show()

    def _on_error(self, err: str) -> None:
        self.btn_lookup.setEnabled(True)
        self.spinner.stop()
        self.progress_row.hide()
        self.error_lbl.setText(f"Lookup failed: {err}")
        self.empty.show()

    # ---------------------------------------------------------------- render
    def _render(self, report: dict) -> None:
        ind = report["indicator"]
        risk = report["risk"]
        self.gauge.set_score(risk["score"], risk["severity"], risk.get("verdict", ""))

        # factors
        while self.factors_lay.count():
            item = self.factors_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for f in risk.get("factors", []):
            row = QWidget()
            r = QHBoxLayout(row)
            r.setContentsMargins(2, 2, 2, 2)
            sign = "+" if f["impact"] >= 0 else ""
            impact = label(f"{sign}{f['impact']}", "", wordwrap=False)
            impact.setStyleSheet(
                f"color: {'#16A34A' if f['impact'] >= 0 else '#DC2626'};"
                f"font-weight: 800; font-size: 13px; min-width: 34px;"
            )
            r.addWidget(impact)
            col = QVBoxLayout()
            t = label(f["label"], "", wordwrap=True)
            t.setStyleSheet("font-weight: 650; font-size: 12.5px;")
            col.addWidget(t)
            if f.get("detail"):
                d = label(f["detail"], "Muted")
                col.addWidget(d)
            r.addLayout(col, 1)
            self.factors_lay.addWidget(row)

        # context
        meta = (ind.get("meta") or {})
        lat = meta.get("lat")
        lon = meta.get("lon")
        self.context.set_items([
            ("Value", ind["value"]),
            ("Type", ind["type"].upper()),
            ("Country", ind.get("country") or "—"),
            ("ASN", ind.get("asn") or "—"),
            ("ASN name", ind.get("asn_name") or "—"),
            ("First seen", relative_time(ind.get("first_seen"))),
            ("Last seen", relative_time(ind.get("last_seen"))),
            ("Sources", ", ".join(report.get("sources_queried") or []) or "—"),
            ("Relationships added", str(report.get("relationships_added", 0))),
        ], mono_keys=("Value", "ASN"))
        self.map.set_plot_points([{
            "value": ind["value"], "label": ind["value"], "lat": lat, "lon": lon,
            "severity": risk["severity"],
        }])
        self.map.set_demo_mode(report.get("demo", False))

        # mitre chips
        while self.mitre_area.layout().count():
            item = self.mitre_area.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        mitre = report.get("mitre") or []
        if not mitre:
            self.mitre_area.layout().addWidget(
                label("No technique associations derived from current evidence.", "Muted"))
        else:
            for m in mitre[:8]:
                self.mitre_area.layout().addWidget(Badge(f"{m['id']} · {m['name']}", "primary"))
        self.mitre_area.layout().addStretch(1)

        # findings
        while self.sources_lay.count():
            item = self.sources_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        findings = report.get("findings") or []
        if not findings:
            self.sources_lay.addWidget(label(
                "No configured provider returned findings for this indicator.", "Muted"))
        for f in findings:
            self.sources_lay.addWidget(self._finding_card(f))
        # unconfigured providers hint
        missing = [p.display_name for p in self.hub().engine.providers.values()
                   if p.requires_key and not p.is_configured()]
        if missing:
            self.sources_lay.addWidget(Banner(
                f"Not queried (no API key): {', '.join(missing)} — configure them in "
                "Settings → Intelligence Sources for fuller coverage.", "info"))
        self.cache_lbl.setText(
            "Demonstration data" if report.get("demo") else "Live provider data")

    def _finding_card(self, f: dict) -> QWidget:
        card = Card(flat=False, shadow=False)
        card.setStyleSheet(f"Card {{ background: {theme.COLORS['surface_alt']};"
                           f" border: 1px solid {theme.COLORS['divider']}; border-radius: 12px; }}")
        head = QHBoxLayout()
        head.addWidget(label(f["source"], "H3", wordwrap=False))
        head.addStretch(1)
        head.addWidget(severity_badge := Badge((f.get("severity") or "info").upper(),
                                               f.get("severity") or "info"))
        card.layout().addLayout(head)

        body = QHBoxLayout()
        # score bar
        bar_host = QWidget()
        bar_host.setFixedWidth(150)
        from PySide6.QtCore import QRectF
        from PySide6.QtGui import QColor, QPainter

        class ScoreBar(QWidget):
            def __init__(self, score, color):
                super().__init__()
                self.s, self.c = score, color
                self.setMinimumHeight(14)

            def paintEvent(self, _e):  # noqa: N802
                p = QPainter(self)
                p.setRenderHint(QPainter.RenderHint.Antialiasing)
                w = self.width()
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(theme.COLORS["divider"]))
                p.drawRoundedRect(QRectF(0, 3, w, 8), 4, 4)
                if self.s:
                    p.setBrush(QColor(self.c))
                    p.drawRoundedRect(QRectF(0, 3, w * self.s / 100, 8), 4, 4)

        score = f.get("score")
        color = theme.SEVERITY_COLORS.get(f.get("severity", "info"))
        bar = ScoreBar(score if score is not None else 0, color)
        bl2 = QVBoxLayout(bar_host)
        bl2.setContentsMargins(0, 4, 8, 4)
        bl2.addWidget(bar)
        sval = label(f"{score}/100" if score is not None else "no score", "Muted", wordwrap=False)
        bl2.addWidget(sval)
        body.addWidget(bar_host)

        txt = QVBoxLayout()
        txt.addWidget(label(f.get("summary") or "No summary provided.", "", wordwrap=True))
        meta_bits = []
        data = f.get("data") or {}
        for key in ("reports", "pulse_count", "engines_total", "url_count", "ioc_count"):
            if key in data:
                meta_bits.append(f"{key.replace('_', ' ')}: {data[key]}")
        if f.get("tags"):
            meta_bits.append("tags: " + ", ".join(f["tags"][:6]))
        if meta_bits:
            txt.addWidget(label(" · ".join(meta_bits), "Muted"))
        txt.addWidget(label(f"observed {relative_time(f.get('observed_at'))} · "
                            f"confidence {round((f.get('confidence') or 0) * 100)}%", "Muted"))
        body.addLayout(txt, 1)
        card.layout().addLayout(body)
        return card

    # --------------------------------------------------------------- actions
    def _add_to_investigation(self) -> None:
        if not self._last_report:
            return
        from ...ui.dialogs.common import TextDialog

        hub = self.hub()
        invs = hub.repo.list_investigations()
        dlg = TextDialog(self, "Add to investigation — enter investigation name",
                         placeholder="New or existing investigation name",
                         initial=invs[0]["name"] if invs else "")
        if not dlg.exec():
            return
        name = dlg.value()
        existing = next((i for i in invs if i["name"].lower() == name.lower()), None)
        inv_id = existing["id"] if existing else hub.repo.create_investigation(name)
        iid = hub.repo.get_indicator_by_value(self._last_report["indicator"]["value"])
        hub.repo.add_investigation_item(inv_id, iid["id"],
                                        note=f"Added from IP Investigation ({relative_time(None)})")
        self.hub().events.publish("investigation.updated",
                                  f"Indicator added to investigation '{name}'", severity="success")

    def _copy_json(self) -> None:
        if not self._last_report:
            return
        import json

        QGuiApplication.clipboard().setText(json.dumps(self._last_report, indent=2, default=str))
        self.hub().events.publish("ui.copy", "Investigation JSON copied to clipboard",
                                  severity="info")
