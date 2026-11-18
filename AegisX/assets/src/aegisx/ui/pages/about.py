"""
AegisX — About page.

Brand story, capabilities, technology stack, developer credit, license and
disclaimers, plus real runtime environment information.
"""

from __future__ import annotations

import platform
import sys

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

import PySide6
import pyqtgraph

from ...styles import theme
from ..components import Badge, Card, label
from ..logo import paint_shield
from ...version import (
    APP_AUTHOR,
    APP_MOTTO,
    APP_NAME,
    APP_TAGLINE,
    APP_VERSION,
)
from .base_page import PageBase


class _LogoLabel(QLabel):
    """QLabel subclass painting the AegisX shield mark."""

    def __init__(self, size: int) -> None:
        super().__init__()
        self._size = size
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        paint_shield(p, QRectF(0, 0, self._size, self._size), size=self._size - 4)
        p.end()


class AboutPage(PageBase):
    title = "About AegisX"
    subtitle = "Next-Generation Global Cyber Threat Intelligence for Kali Linux."
    page_key = "about"

    def build(self) -> None:
        # hero
        hero = Card()
        hl = QHBoxLayout()
        logo = _LogoLabel(108)
        hl.addWidget(logo)

        col = QVBoxLayout()
        title_row = QHBoxLayout()
        t = QLabel("AegisX")
        t.setStyleSheet("font-size: 30px; font-weight: 800; color: #111827; background: transparent;")
        title_row.addWidget(t)
        tx = QLabel("X")
        tx.setStyleSheet(
            f"font-size: 30px; font-weight: 800; color: {theme.COLORS['primary']}; background: transparent;")
        title_row.addWidget(tx)
        title_row.addStretch(1)
        col.addLayout(title_row)
        col.addWidget(label(APP_TAGLINE.upper(), "Overline"))
        col.addWidget(label(
            "A centralized Global Cyber Threat Intelligence platform: collect, analyze, "
            "correlate and visualize malicious infrastructure, then produce professional "
            "investigation reports — entirely on your Kali Linux workstation.", "Subtitle"))
        chips = QHBoxLayout()
        chips.addWidget(Badge(f"v{APP_VERSION}", "primary"))
        chips.addWidget(Badge("Designed for Kali Linux", "info"))
        chips.addWidget(Badge("MIT License", "info"))
        chips.addWidget(Badge(f"by {APP_AUTHOR}", "demo"))
        chips.addStretch(1)
        col.addLayout(chips)
        hl.addLayout(col, 1)
        hero.layout().addLayout(hl)
        self.body_lay.addWidget(hero)

        # feature grid
        card_f = Card()
        card_f.layout().addWidget(label("Capabilities", "H2"))
        feats = [
            ("Multi-source intelligence", "AbuseIPDB, VirusTotal, AlienVault OTX, URLhaus, ThreatFox and GeoIP adapters with caching and rate limiting."),
            ("Evidence-based risk scoring", "Transparent 0-100 scoring with factor breakdown, confidence and severity bands."),
            ("Infrastructure correlation", "Shared-ASN, DNS resolution, campaign and tag-similarity relationships with cluster analysis."),
            ("Interactive global map", "Dot-matrix world map with animated attack flows and approximate geolocation."),
            ("Campaign intelligence", "Clustered campaigns, timelines and MITRE ATT&CK technique associations."),
            ("Professional reports", "Self-contained branded HTML/JSON reports with methodology and disclaimers."),
        ]
        grid_host = QWidget()
        gl = QGridLayout(grid_host)
        gl.setSpacing(14)
        for i, (t2, d2) in enumerate(feats):
            box = QVBoxLayout()
            box.setSpacing(3)
            box.addWidget(label(t2, "H3"))
            box.addWidget(label(d2, "Muted"))
            cell = QWidget()
            cell.setLayout(box)
            cell.setMinimumHeight(64)
            gl.addWidget(cell, i % 3, i // 3)
        gl.setColumnStretch(0, 1)
        gl.setColumnStretch(1, 1)
        card_f.layout().addWidget(grid_host)
        self.body_lay.addWidget(card_f)

        # developer + stack + environment
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setSpacing(14)

        card_dev = Card()
        card_dev.layout().addWidget(label("Developer", "H2"))
        card_dev.layout().addWidget(label(
            f"{APP_NAME} is developed and maintained by {APP_AUTHOR}.", "", wordwrap=True))
        card_dev.layout().addWidget(label(APP_MOTTO, "Subtitle"))
        card_dev.layout().addWidget(label(
            "Built for the Kali Linux community. Secure · Analyze · Investigate · Protect.",
            "Muted"))
        rl.addWidget(card_dev, 1)

        card_stack = Card()
        card_stack.layout().addWidget(label("Technology Stack", "H2"))
        self.stack = _KV()
        card_stack.layout().addWidget(self.stack, 1)
        rl.addWidget(card_stack, 1)
        self.body_lay.addWidget(row)

        card_d = Card()
        card_d.layout().addWidget(label("Methodology & Disclaimers", "H2"))
        card_d.layout().addWidget(label(
            "AegisX aggregates Open-Source Intelligence (OSINT) from third-party providers. "
            "Risk scores are evidence-weighted estimates — every score lists its contributing "
            "factors. MITRE ATT&CK associations are behaviour-derived and indicative, not "
            "definitive. AegisX never asserts threat-actor attribution: attribution shown in "
            "the interface originates from provider pulse metadata and is always accompanied "
            "by its stated confidence. Demonstration mode uses RFC 5737 documentation "
            "addresses and reserved example domains and is labelled everywhere it appears.",
            "", wordwrap=True))
        card_d.layout().addWidget(label(
            "This software is provided under the MIT License, without warranty of any kind. "
            "Use responsibly and in accordance with your local laws and provider terms.",
            "Muted"))
        self.body_lay.addWidget(card_d)

    def refresh(self) -> None:
        hub = self.hub()
        self.stack.set_items([
            ("Version", f"{APP_VERSION}"),
            ("Python", sys.version.split()[0]),
            ("PySide6 (Qt)", PySide6.__version__),
            ("PyQtGraph", pyqtgraph.__version__),
            ("Platform", f"{platform.system()} {platform.release()}"),
            ("Install type", _install_type()),
            ("Database", str(hub.repo.db_path)),
        ])


def _KV():
    from ..components import KVWidget

    return KVWidget()


def _install_type() -> str:
    from ...utils.paths import is_installed_permanently

    return "Permanent (/opt/AegisX)" if is_installed_permanently() else "Source tree"
