"""
AegisX — Domain Intelligence page.

DNS resolution, TLS certificate intelligence and provider reputation for
domain indicators, with resolution-derived relationships.
"""

from __future__ import annotations

import socket
import ssl

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...providers.base import ProviderError
from ...styles import theme
from ...utils.validators import normalize_domain
from ...workers import TaskManager
from ..components import (
    Badge,
    Banner,
    Card,
    EmptyState,
    GaugeWidget,
    GhostButton,
    KVWidget,
    PrimaryButton,
    Spinner,
    label,
)
from .base_page import PageBase


def resolve_dns(domain: str) -> dict:
    """Real DNS resolution (A/AAAA + reverse). Graceful on failure."""
    out: dict = {"a": [], "aaaa": [], "reverse": [], "error": ""}
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        for fam, _typ, _proto, _canon, sa in infos:
            ip = sa[0]
            if fam == socket.AF_INET and ip not in out["a"]:
                out["a"].append(ip)
            elif fam == socket.AF_INET6 and ip not in out["aaaa"]:
                out["aaaa"].append(ip)
    except socket.gaierror as e:
        out["error"] = f"DNS resolution failed: {e}"
    return out


def fetch_certificate(domain: str, timeout: float = 6.0) -> dict:
    """Real TLS certificate inspection over port 443. Graceful on failure."""
    out: dict = {"present": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:10]
            out = {
                "present": True,
                "subject_cn": subject.get("commonName", ""),
                "organization": subject.get("organizationName", ""),
                "issuer": issuer.get("organizationName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "serial": cert.get("serialNumber", ""),
                "san": san,
            }
    except Exception as e:  # noqa: BLE001 - offline hosts are normal
        out["error"] = f"No TLS service / certificate unavailable: {e}"
    return out


class DomainIntelligencePage(PageBase):
    title = "Domain Intelligence"
    subtitle = "DNS, certificate and reputation intelligence for suspicious domains."
    page_key = "domain_intelligence"

    def build(self) -> None:
        self.maybe_demo_banner()

        search_card = Card()
        sl = QHBoxLayout()
        sl.setSpacing(10)
        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter a domain — e.g. malware.example")
        self.input.setFixedHeight(42)
        self.input.returnPressed.connect(self.run_lookup)
        sl.addWidget(self.input, 1)
        self.btn_lookup = PrimaryButton("Investigate", "search")
        self.btn_lookup.setFixedHeight(42)
        self.btn_lookup.clicked.connect(self.run_lookup)
        sl.addWidget(self.btn_lookup)
        search_card.layout().addLayout(sl)
        self.error_lbl = label("", "Muted")
        self.error_lbl.setStyleSheet("color: #DC2626; font-size: 12px;")
        search_card.layout().addWidget(self.error_lbl)
        self.body_lay.addWidget(search_card)

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

        self.results = QWidget()
        rl = QVBoxLayout(self.results)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(14)

        # verdict + dns/cert
        top = QWidget()
        tr = QHBoxLayout(top)
        tr.setContentsMargins(0, 0, 0, 0)
        tr.setSpacing(14)
        card_gauge = Card()
        card_gauge.layout().addWidget(label("Reputation Verdict", "H3"))
        self.gauge = GaugeWidget()
        card_gauge.layout().addWidget(self.gauge, 1)
        self.verdict_lbl = label("", "Subtitle")
        self.verdict_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_gauge.layout().addWidget(self.verdict_lbl)
        tr.addWidget(card_gauge, 1)

        card_dns = Card()
        card_dns.layout().addWidget(label("DNS Records", "H3"))
        self.dns = KVWidget()
        card_dns.layout().addWidget(self.dns, 1)
        tr.addWidget(card_dns, 1)
        rl.addWidget(top)

        # certificate
        card_cert = Card()
        card_cert.layout().addWidget(label("TLS Certificate Intelligence", "H3"))
        self.cert = KVWidget()
        card_cert.layout().addWidget(self.cert, 1)
        rl.addWidget(card_cert)

        # provider findings
        card_sources = Card()
        card_sources.layout().addWidget(label("Source Findings", "H3"))
        self.sources_area = QWidget()
        self.sources_lay = QVBoxLayout(self.sources_area)
        self.sources_lay.setContentsMargins(0, 0, 0, 0)
        self.sources_lay.setSpacing(10)
        card_sources.layout().addWidget(self.sources_area, 1)
        rl.addWidget(card_sources)

        actions = QWidget()
        al = QHBoxLayout(actions)
        al.setContentsMargins(0, 0, 0, 0)
        self.btn_add_inv = PrimaryButton("Add to investigation", "plus")
        self.btn_add_inv.clicked.connect(self._add_to_investigation)
        al.addWidget(self.btn_add_inv)
        self.btn_copy = GhostButton("Copy JSON", "file")
        self.btn_copy.clicked.connect(self._copy_json)
        al.addWidget(self.btn_copy)
        al.addStretch(1)
        rl.addWidget(actions)

        self.empty = EmptyState(
            "Run a domain investigation",
            "Enter any domain — AegisX resolves DNS, inspects the TLS certificate and "
            "queries every configured reputation source.",
            icon_name="link",
        )
        rl.addWidget(self.empty)
        self.body_lay.addWidget(self.results, 1)
        self.results.hide()
        self._last_report = None

    # ----------------------------------------------------------------- lookup
    def run_lookup(self) -> None:
        value = self.input.text().strip().lower()
        if not value:
            self.error_lbl.setText("Enter a domain first.")
            return
        norm = normalize_domain(value)
        if not norm:
            self.error_lbl.setText("Not a valid domain name.")
            return
        self.error_lbl.setText("")
        self.btn_lookup.setEnabled(False)
        self.results.hide()
        self.empty.hide()
        self.progress_row.show()
        self.spinner.start()
        self.progress_lbl.setText("Resolving DNS…")

        TaskManager.get().submit(
            self._pipeline, value,
            description=f"domain-lookup {value}",
            on_done=self._on_result, on_error=self._on_error,
        )

    def _pipeline(self, domain: str) -> dict:
        """Runs on a worker thread: DNS + cert + provider lookup."""
        dns = resolve_dns(domain)
        cert = fetch_certificate(domain)
        hub = self.hub()
        report = hub.engine.lookup(domain)
        return {"dns": dns, "cert": cert, "report": report}

    def _on_result(self, data: dict) -> None:
        self.btn_lookup.setEnabled(True)
        self.spinner.stop()
        self.progress_row.hide()
        report = data.get("report")
        if not report:
            self.error_lbl.setText("Analysis returned no report.")
            return
        self._last_report = {"dns": data["dns"], "cert": data["cert"], "report": report}
        dns, cert = data["dns"], data["cert"]

        self.gauge.set_score(report["risk"]["score"], report["risk"]["severity"],
                             report["risk"].get("verdict", ""))
        self.verdict_lbl.setText(report["risk"].get("verdict", ""))

        self.dns.set_items([
            ("Domain", report["indicator"]["value"]),
            ("A records", ", ".join(dns["a"]) or "—"),
            ("AAAA records", ", ".join(dns["aaaa"]) or "—"),
            ("Resolution status", dns["error"] or "Resolved"),
        ], mono_keys=("A records", "AAAA records", "Domain"))

        if cert.get("present"):
            self.cert.set_items([
                ("Subject CN", cert.get("subject_cn", "—")),
                ("Organization", cert.get("organization", "—")),
                ("Issuer", cert.get("issuer", "—")),
                ("Valid from", cert.get("not_before", "—")),
                ("Valid until", cert.get("not_after", "—")),
                ("SAN entries", ", ".join(cert.get("san", [])[:6]) or "—"),
            ])
        else:
            self.cert.set_items([("Certificate", cert.get("error") or "Not available")])

        # findings
        while self.sources_lay.count():
            item = self.sources_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        findings = report.get("findings") or []
        if not findings:
            self.sources_lay.addWidget(label(
                "No configured provider returned findings for this domain.", "Muted"))
        for f in findings:
            card = Card(flat=False, shadow=False)
            card.setStyleSheet(
                f"Card {{ background: {theme.COLORS['surface_alt']};"
                f" border: 1px solid {theme.COLORS['divider']}; border-radius: 12px; }}")
            head = QHBoxLayout()
            head.addWidget(label(f["source"], "H3", wordwrap=False))
            head.addStretch(1)
            head.addWidget(Badge((f.get("severity") or "info").upper(), f.get("severity") or "info"))
            card.layout().addLayout(head)
            card.layout().addWidget(label(f.get("summary") or "", "", wordwrap=True))
            if f.get("tags"):
                tags = label("tags: " + ", ".join(f["tags"][:8]), "Muted")
                card.layout().addWidget(tags)
            self.sources_lay.addWidget(card)

        missing = [p.display_name for p in self.hub().engine.providers.values()
                   if p.requires_key and not p.is_configured()]
        if missing:
            self.sources_lay.addWidget(Banner(
                f"Not queried (no API key): {', '.join(missing)}.", "info"))

        self.results.show()
        self.maybe_demo_banner()

    def _on_error(self, err: str) -> None:
        self.btn_lookup.setEnabled(True)
        self.spinner.stop()
        self.progress_row.hide()
        self.error_lbl.setText(f"Lookup failed: {err}")

    # ---------------------------------------------------------------- actions
    def _add_to_investigation(self) -> None:
        if not self._last_report:
            return
        from ...ui.dialogs.common import TextDialog

        hub = self.hub()
        dlg = TextDialog(self, "Add to investigation — enter investigation name",
                         placeholder="New or existing investigation name")
        if not dlg.exec():
            return
        name = dlg.value()
        invs = hub.repo.list_investigations()
        existing = next((i for i in invs if i["name"].lower() == name.lower()), None)
        inv_id = existing["id"] if existing else hub.repo.create_investigation(name)
        ind = hub.repo.get_indicator_by_value(self._last_report["report"]["indicator"]["value"])
        hub.repo.add_investigation_item(inv_id, ind["id"])
        hub.events.publish("investigation.updated",
                           f"Domain added to investigation '{name}'", severity="success")

    def _copy_json(self) -> None:
        if not self._last_report:
            return
        import json

        QGuiApplication.clipboard().setText(json.dumps(self._last_report, indent=2, default=str))
        self.hub().events.publish("ui.copy", "Domain intelligence JSON copied",
                                  severity="info")
