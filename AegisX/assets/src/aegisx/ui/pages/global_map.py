"""
AegisX — Global Threat Map page.

Full-width interactive map with severity/type filters, demo activity feed,
selected-marker detail panel and live country statistics.
"""

from __future__ import annotations

import random

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ...visualization.mapdata import CITIES
from ...visualization.threat_map import ThreatMapWidget
from ..components import (
    Badge,
    Card,
    EmptyState,
    GhostButton,
    KVWidget,
    PrimaryButton,
    label,
)
from .base_page import PageBase

SEVS = ("", "critical", "high", "medium", "low", "info")


class GlobalMapPage(PageBase):
    title = "Global Threat Map"
    subtitle = "Approximate geographic plotting of tracked indicators and observed activity."
    page_key = "global_map"

    def build(self) -> None:
        self.maybe_demo_banner()

        # filter bar
        bar = QWidget()
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(10)
        bl.addWidget(label("Severity", "H3", wordwrap=False))
        self.sev_combo = QComboBox()
        self.sev_combo.addItems(["All severities", "Critical", "High", "Medium", "Low", "Info"])
        self.sev_combo.currentIndexChanged.connect(lambda _i: self.refresh())
        bl.addWidget(self.sev_combo)
        bl.addWidget(label("Type", "H3", wordwrap=False))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All types", "IP", "IPv6", "Domain"])
        self.type_combo.currentIndexChanged.connect(lambda _i: self.refresh())
        bl.addWidget(self.type_combo)
        bl.addStretch(1)
        self.btn_live = GhostButton("Pause animation", "play")
        self.btn_live.clicked.connect(self._toggle_anim)
        bl.addWidget(self.btn_live)
        self.btn_demo_feed = PrimaryButton("Start demonstration feed", "zap")
        self.btn_demo_feed.clicked.connect(self._toggle_demo_feed)
        bl.addWidget(self.btn_demo_feed)
        self.body_lay.addWidget(bar)

        # main map + side panel
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(14)

        card_map = Card()
        self.map = ThreatMapWidget()
        self.map.marker_selected.connect(self._on_marker)
        card_map.layout().addWidget(self.map, 1)
        card_map.setMinimumHeight(520)
        rl.addWidget(card_map, 4)

        side = Card()
        side.layout().addWidget(label("Selected Marker", "H3"))
        self.detail = KVWidget()
        side.layout().addWidget(self.detail)
        side.layout().addStretch(1)
        self.btn_investigate = PrimaryButton("Open full investigation", "target")
        self.btn_investigate.setEnabled(False)
        self.btn_investigate.clicked.connect(self._investigate)
        side.layout().addWidget(self.btn_investigate)
        rl.addWidget(side, 1)
        self.body_lay.addWidget(row, 1)

        # stats strip
        stats_row = QWidget()
        sl = QHBoxLayout(stats_row)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(14)
        self.lbl_markers = label("0 plotted indicators", "Subtitle")
        self.lbl_countries = label("0 countries", "Subtitle")
        self.lbl_arcs = label("0 active flows", "Subtitle")
        sl.addWidget(self.lbl_markers)
        sl.addWidget(self.lbl_countries)
        sl.addWidget(self.lbl_arcs)
        sl.addStretch(1)
        self.body_lay.addWidget(stats_row)

        self._selected_value = None
        self._feed_timer = QTimer(self)
        self._feed_timer.setInterval(1400)
        self._feed_timer.timeout.connect(self._demo_tick)
        self._demo_feed_on = False

    # ----------------------------------------------------------------- data
    def refresh(self) -> None:
        hub = self.hub()
        demo = hub.demo_mode
        sev_idx = self.sev_combo.currentIndex()
        sev = SEVS[sev_idx] if sev_idx > 0 else ""
        type_map = {0: "", 1: "ip", 2: "ipv6", 3: "domain"}
        t = type_map[self.type_combo.currentIndex()]

        inds = hub.repo.search_indicators(limit=120, order="risk",
                                          demo=demo or None)
        pts = []
        for ind in inds:
            if t and ind["type"] != t:
                continue
            if sev and ind["severity"] != sev:
                continue
            if ind["type"] not in ("ip", "ipv6"):
                continue
            meta = ind.get("meta") or {}
            lat, lon = meta.get("lat"), meta.get("lon")
            if lat is None or lon is None:
                continue
            pts.append({"value": ind["value"], "label": ind["value"],
                        "lat": lat, "lon": lon, "severity": ind["severity"],
                        "city": meta.get("city") or "", "country": ind.get("country") or ""})
        self.map.set_plot_points(pts)
        self.map.set_demo_mode(demo)

        countries = len({p["country"] for p in pts if p["country"]})
        self.lbl_markers.setText(f"{len(pts)} plotted indicators")
        self.lbl_countries.setText(f"{countries} countries represented")

        self.maybe_demo_banner()

    # ------------------------------------------------------------ interactions
    def _toggle_anim(self) -> None:
        if self.map._timer.isActive():
            self.map.stop()
            self.btn_live.setText("Resume animation")
        else:
            self.map.start()
            self.btn_live.setText("Pause animation")

    def _toggle_demo_feed(self) -> None:
        self._demo_feed_on = not self._demo_feed_on
        if self._demo_feed_on:
            self.btn_demo_feed.setText("Stop demonstration feed")
            self._feed_timer.start()
            self._maybe_demo_banner()
        else:
            self.btn_demo_feed.setText("Start demonstration feed")
            self._feed_timer.stop()
            self.map.set_arcs([])

    def _maybe_demo_banner(self) -> None:
        if self._demo_feed_on:
            self.maybe_demo_banner(
                "Demonstration activity feed running — arcs and markers are SAMPLE "
                "traffic between labeled demo locations, not live threat data.")

    def _demo_tick(self) -> None:
        rng = random.Random()
        arcs = []
        for _ in range(rng.randint(2, 5)):
            a, b = rng.sample(CITIES, 2)
            sev = rng.choice(("critical", "high", "medium"))
            arcs.append({"from": (a[1], a[2]), "to": (b[1], b[2]), "severity": sev})
        self.map.set_arcs(arcs)
        self.lbl_arcs.setText(f"{len(arcs)} active flows")

    def _on_marker(self, point: dict) -> None:
        self._selected_value = point.get("value")
        self.detail.set_items([
            ("Indicator", point.get("value", "")),
            ("Approximate location", f"{point.get('city') or 'Unknown'} {point.get('country') or ''}".strip()),
            ("Severity", point.get("severity", "info").upper()),
            ("Coordinates", f"{point.get('lat'):.2f}, {point.get('lon'):.2f}"),
        ], mono_keys=("Indicator", "Coordinates"))
        self.btn_investigate.setEnabled(True)

    def _investigate(self) -> None:
        if not self._selected_value:
            return
        win = self.window()
        if hasattr(win, "navigate"):
            win.navigate("ip_investigation")
            ip_page = win.page("ip_investigation")
            if ip_page and hasattr(ip_page, "set_input"):
                ip_page.set_input(self._selected_value)
                ip_page.run_lookup()
