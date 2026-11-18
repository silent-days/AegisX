"""
AegisX — Dashboard (Command Center).

A centered, next-generation intelligence overview inspired by network
operations consoles: an auto-scrolling alert ticker, a live global threat
network topology at the center of the page, flanked by intelligence
columns (network status, top targeted countries, rotating intelligence
pulse, investigation workspace, severity overview and the top threat
indicators) with an activity timeline and severity donut below.

Everything derives from the local corpus (honest demonstration data when
provider keys are not configured).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.services import ServiceHub
from ...styles import theme
from ...visualization.charts import timeline_chart
from ..components import (
    AlertTicker,
    Card,
    CarouselCard,
    DonutWidget,
    IconButton,
    MetricGauge,
    MiniBarChart,
    RangeChips,
    SegmentBar,
    ThreatTopologyWidget,
    TopIndicatorPanel,
    label,
    relative_time,
)
from ..icons import icon
from .base_page import PageBase

SEV_COLORS = {"critical": "#DC2626", "high": "#F97316", "medium": "#F59E0B",
              "low": "#3B82F6", "info": "#64748B"}
SEV_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium",
              "low": "Low", "info": "Info"}

TYPE_GROUPS = [
    ("ip", "IPs", "Malicious IPs", "#DC2626"),
    ("domain", "Domains", "Phishing Domains", "#F97316"),
    ("url", "URLs", "Malicious URLs", "#F59E0B"),
    ("hash", "Hashes", "File Hashes", "#8B5CF6"),
]

MAX_CONTENT_WIDTH = 1320


class TypeChip(QFrame):
    """Clickable legend chip that toggles a topology cluster."""

    toggled = Signal(str, bool)

    def __init__(self, type_key: str, text: str, color: str, count: int = 0,
                 full_name: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._key, self._color, self._checked = type_key, color, True
        self._count = count
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(full_name or text)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(7, 4, 7, 4)
        lay.setSpacing(6)
        self._dot = QLabel()
        self._dot.setFixedSize(10, 10)
        lay.addWidget(self._dot)
        self._lbl = QLabel(f"{text} ({count})")
        self._lbl.setMinimumWidth(1)
        self._lbl.setStyleSheet("font-size: 10.5px; font-weight: 800; background: transparent;")
        lay.addWidget(self._lbl)
        self._apply_style()
        self._refresh_pixmap()

    def set_count(self, count: int) -> None:
        self._count = count
        text = self._lbl.text().rsplit(" (", 1)[0]
        self._lbl.setText(f"{text} ({count})")

    def _refresh_pixmap(self) -> None:
        col = QColor(self._color) if self._checked else QColor("#C3CBD6")
        self._dot.setStyleSheet(
            f"background: {col.name()}; border-radius: 5px;")

    def _apply_style(self) -> None:
        if self._checked:
            self.setStyleSheet(
                f"TypeChip {{ background: {theme.rgba_hex(self._color, 0.08)};"
                f" border: 1px solid {theme.rgba_hex(self._color, 0.35)};"
                " border-radius: 11px; }"
                f"QLabel {{ color: {self._color}; }}")
        else:
            self.setStyleSheet(
                "TypeChip { background: #F1F5F9; border: 1px solid #E2E8F0;"
                " border-radius: 11px; }"
                "QLabel { color: #94A3B8; }")

    def is_checked(self) -> bool:
        return self._checked

    def mouseReleaseEvent(self, e) -> None:  # noqa: N802
        self._checked = not self._checked
        self._apply_style()
        self._refresh_pixmap()
        self.toggled.emit(self._key, self._checked)
        super().mouseReleaseEvent(e)


class SeverityChip(QFrame):
    """Static colored status chip with painted dot (e.g. 'Critical (26)')."""

    def __init__(self, color: str, text: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(
            f"background: {theme.rgba_hex(color, 0.08)};"
            f" border: 1px solid {theme.rgba_hex(color, 0.30)};"
            " border-radius: 11px;")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(7, 3, 8, 3)
        lay.setSpacing(6)
        self._dot = QLabel()
        self._dot.setFixedSize(8, 8)
        self._dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
        lay.addWidget(self._dot)
        self._lbl = QLabel(text)
        self._lbl.setMinimumWidth(1)
        self._lbl.setStyleSheet(
            f"color: {color}; font-size: 10.5px; font-weight: 800; background: transparent;")
        lay.addWidget(self._lbl)

    def set_text(self, text: str) -> None:
        self._lbl.setText(text)


def _card_header(title: str, icon_name: str, accent: str) -> QWidget:
    head = QWidget()
    hl = QHBoxLayout(head)
    hl.setContentsMargins(0, 0, 0, 0)
    hl.setSpacing(9)
    ic = QLabel()
    ic.setPixmap(icon(icon_name, accent, 16).pixmap(16, 16))
    ic.setStyleSheet(
        f"background: {theme.rgba_hex(accent, 0.12)}; border-radius: 8px; padding: 6px;")
    hl.addWidget(ic)
    hl.addWidget(label(title, "H3", wordwrap=False), 1)
    return head


def _nav_row(text: str, value: str, color: str) -> QFrame:
    row = QFrame()
    row.setCursor(Qt.CursorShape.PointingHandCursor)
    row.setStyleSheet(
        "QFrame { background: transparent; border-radius: 8px; }"
        f"QFrame:hover {{ background: {theme.COLORS['hover']}; }}")
    rl = QHBoxLayout(row)
    rl.setContentsMargins(8, 6, 8, 6)
    rl.setSpacing(8)
    t = label(text, "", wordwrap=False)
    t.setStyleSheet("font-size: 12.5px; font-weight: 600; color: #374151; background: transparent;")
    rl.addWidget(t, 1)
    v = label(value, "", wordwrap=False)
    v.setStyleSheet(f"font-size: 13px; font-weight: 900; color: {color}; background: transparent;")
    rl.addWidget(v)
    ch = QLabel()
    ch.setPixmap(icon("chevron-right", "#C3CBD6", 13).pixmap(13, 13))
    ch.setStyleSheet("background: transparent;")
    rl.addWidget(ch)
    row._value_lbl = v
    return row


class DashboardPage(PageBase):
    title = "Welcome back, Security Researcher"
    subtitle = "Your command center — monitor, analyze, investigate."

    page_key = "dashboard"

    def build(self) -> None:
        self.maybe_demo_banner()
        self._range_days = 7

        # ---- scroll host (same pattern as before) -------------------------
        self.page_scroll = QScrollArea()
        self.page_scroll.setWidgetResizable(True)
        self.page_scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        self.body_lay.setContentsMargins(0, 0, 0, 0)
        content_lay = QVBoxLayout(content)
        content_lay.setContentsMargins(0, 0, 0, 0)
        content_lay.setSpacing(0)
        self._inner_body = QWidget()
        inner_lay = QVBoxLayout(self._inner_body)
        inner_lay.setContentsMargins(0, 0, 0, 0)
        inner_lay.setSpacing(0)
        self.body.setParent(self._inner_body)
        inner_lay.addWidget(self.body)
        content_lay.addWidget(self._inner_body)
        self.page_scroll.setWidget(content)
        self._root_lay.addWidget(self.page_scroll, 1)

        # ---- centered column ----------------------------------------------
        wrap = QWidget()
        wl = QHBoxLayout(wrap)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.setSpacing(0)
        center = QWidget()
        self._center_lay = QVBoxLayout(center)
        self._center_lay.setContentsMargins(0, 0, 0, 0)
        self._center_lay.setSpacing(14)
        center.setMaximumWidth(MAX_CONTENT_WIDTH)
        wl.addStretch(1)
        wl.addWidget(center, 1)
        wl.addStretch(1)
        self.body_lay.addWidget(wrap)

        # ---- ticker + range row -------------------------------------------
        top_row = QWidget()
        tr = QHBoxLayout(top_row)
        tr.setContentsMargins(0, 0, 0, 0)
        tr.setSpacing(12)
        self.ticker = AlertTicker()
        self.ticker.see_all.connect(self._goto_threat_intel)
        tr.addWidget(self.ticker, 1)
        self.range_chips = RangeChips()
        self.range_chips.range_changed.connect(self._on_range_changed)
        tr.addWidget(self.range_chips, 0)
        self._center_lay.addWidget(top_row)

        # ---- command metrics strip: 3D gauges ------------------------------
        card_metrics = Card()
        head_row = QHBoxLayout()
        head_row.addWidget(_card_header("Command Metrics — Live Posture", "gauge",
                                        theme.COLORS["primary"]))
        head_row.addStretch(1)
        self.metrics_hint = label("animated · auto-refresh every 30 s", "Muted",
                                  wordwrap=False)
        self.metrics_hint.setStyleSheet("font-size: 10.5px; color: #94A3B8;")
        head_row.addWidget(self.metrics_hint)
        card_metrics.layout().addLayout(head_row)

        gauges_row = QHBoxLayout()
        gauges_row.setSpacing(10)
        self.gauge_threat = MetricGauge("Threat Index", SEV_COLORS["critical"],
                                        caption="avg risk")
        self.gauge_conf = MetricGauge("Detection Confidence", SEV_COLORS["low"],
                                      caption="provider avg")
        self.gauge_exposure = MetricGauge("High-Risk Exposure", SEV_COLORS["high"],
                                          caption="critical + high")
        self.gauge_integrity = MetricGauge("Corpus Coverage", SEV_COLORS["medium"],
                                           caption="type coverage")
        for g in (self.gauge_threat, self.gauge_conf,
                  self.gauge_exposure, self.gauge_integrity):
            gauges_row.addWidget(g, 1)
        card_metrics.layout().addLayout(gauges_row)
        self._center_lay.addWidget(card_metrics)

        # ---- main row: left column | hero topology | right column ---------
        main_row = QWidget()
        mr = QHBoxLayout(main_row)
        mr.setContentsMargins(0, 0, 0, 0)
        mr.setSpacing(14)

        mr.addWidget(self._build_left_column(), 0)
        mr.addWidget(self._build_hero(), 1)
        mr.addWidget(self._build_right_column(), 0)
        self._center_lay.addWidget(main_row, 3)

        # ---- bottom row: timeline + donut ---------------------------------
        bottom = QWidget()
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(14)
        card_timeline = Card()
        self.timeline_title = label("Threat Activity — last 7 days", "H3")
        card_timeline.layout().addWidget(self.timeline_title)
        self.timeline_host = QWidget()
        tl = QVBoxLayout(self.timeline_host)
        tl.setContentsMargins(0, 0, 0, 0)
        card_timeline.layout().addWidget(self.timeline_host, 1)
        card_timeline.setMinimumHeight(250)
        bl.addWidget(card_timeline, 3)

        card_donut = Card()
        card_donut.layout().addWidget(label("Threat Severity Distribution", "H3"))
        self.donut = DonutWidget()
        card_donut.layout().addWidget(self.donut, 1)
        card_donut.setMinimumHeight(250)
        bl.addWidget(card_donut, 2)
        self._center_lay.addWidget(bottom, 2)
        self._center_lay.addStretch(1)

    # ------------------------------------------------------------- columns
    def _build_left_column(self) -> QWidget:
        col = QWidget()
        cl = QVBoxLayout(col)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(14)
        col.setFixedWidth(280)

        # threat network status
        card = Card()
        card.layout().addWidget(_card_header("Threat Network Status", "radar",
                                             theme.COLORS["primary"]))
        big_row = QHBoxLayout()
        big_row.setSpacing(8)
        self.status_total = label("0", "BigNumber", wordwrap=False)
        big_row.addWidget(self.status_total)
        unit = label("Indicators", "Subtitle", wordwrap=False)
        unit.setStyleSheet("font-size: 12px; color: #64748B; padding-top: 14px;")
        big_row.addWidget(unit)
        big_row.addStretch(1)
        card.layout().addLayout(big_row)
        self.sev_bar = SegmentBar()
        card.layout().addWidget(self.sev_bar)
        self.status_legend = QWidget()
        self._status_legend_lay = QGridLayout(self.status_legend)
        self._status_legend_lay.setContentsMargins(0, 0, 0, 0)
        self._status_legend_lay.setHorizontalSpacing(14)
        self._status_legend_lay.setVerticalSpacing(4)
        card.layout().addWidget(self.status_legend)
        cl.addWidget(card)

        # top targeted countries
        card2 = Card()
        card2.layout().addWidget(_card_header("Top Targeted Countries", "globe",
                                              "#3B82F6"))
        self.countries_bars = MiniBarChart()
        card2.layout().addWidget(self.countries_bars, 1)
        self.countries_hint = label(
            "Geo-enrichment pending — configure MaxMind GeoIP to unlock "
            "country-level insight.", "Muted")
        self.countries_hint.setMinimumWidth(1)
        self.countries_hint.hide()
        card2.layout().addWidget(self.countries_hint)
        card2.setMinimumHeight(210)
        cl.addWidget(card2, 1)

        # intelligence pulse carousel
        card3 = Card()
        card3.layout().addWidget(_card_header("Intelligence Pulse", "zap",
                                              "#F59E0B"))
        self.carousel = CarouselCard()
        self.carousel.setMinimumHeight(96)
        card3.layout().addWidget(self.carousel, 1)
        cl.addWidget(card3)

        # investigation workspace
        card4 = Card()
        card4.layout().addWidget(_card_header("Investigation Workspace", "briefcase",
                                              "#8B5CF6"))
        self.nav_invest = _nav_row("Open Investigations", "0", "#111827")
        self.nav_campaigns = _nav_row("Campaigns Tracked", "0", "#111827")
        self.nav_reports = _nav_row("Reports Generated", "0", "#111827")
        for row, key in ((self.nav_invest, "investigations"),
                         (self.nav_campaigns, "campaigns"),
                         (self.nav_reports, "reports")):
            row.mouseReleaseEvent = lambda _e, k=key: self._navigate(k)
            card4.layout().addWidget(row)
        cl.addWidget(card4)
        return col

    def _build_hero(self) -> QWidget:
        hero = QFrame()
        hero.setObjectName("HeroCanvas")
        hero.setStyleSheet(
            "QFrame#HeroCanvas { background: qradialgradient(cx:0.5, cy:0.5,"
            " radius:0.75, fx:0.5, fy:0.5, stop:0 #FFFFFF, stop:1 #F8FAFC);"
            " border: 1px solid #EEF1F5; border-radius: 16px; }")
        add_shadow_effect = QGraphicsDropShadowEffect(hero)
        add_shadow_effect.setBlurRadius(24)
        add_shadow_effect.setOffset(0, 4)
        add_shadow_effect.setColor(QColor(17, 24, 39, 20))
        hero.setGraphicsEffect(add_shadow_effect)

        hl = QVBoxLayout(hero)
        hl.setContentsMargins(14, 12, 14, 12)
        hl.setSpacing(6)

        # search overlay row
        search_row = QWidget()
        sr = QHBoxLayout(search_row)
        sr.setContentsMargins(0, 0, 0, 0)
        sr.addStretch(1)
        self.hero_search = QLineEdit()
        self.hero_search.setPlaceholderText("Search indicators…")
        self.hero_search.setFixedWidth(340)
        self.hero_search.setClearButtonEnabled(True)
        self.hero_search.addAction(icon("search", "#94A3B8", 15),
                                   QLineEdit.ActionPosition.LeadingPosition)
        self.hero_search.setStyleSheet(
            "QLineEdit { background: #FFFFFF; border: 1px solid #E5E7EB;"
            " border-radius: 11px; padding: 7px 14px; font-size: 12.5px; }"
            "QLineEdit:focus { border: 1px solid #FCA5A5; }")
        self.hero_search.returnPressed.connect(self._search_indicator)
        sr.addWidget(self.hero_search)
        sr.addStretch(1)
        hl.addWidget(search_row)

        # topology + zoom rail
        body_row = QWidget()
        br = QHBoxLayout(body_row)
        br.setContentsMargins(0, 0, 0, 0)
        br.setSpacing(8)
        self.topology = ThreatTopologyWidget()
        self.topology.node_selected.connect(self._open_indicator)
        br.addWidget(self.topology, 1)

        rail = QWidget()
        rl = QVBoxLayout(rail)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)
        rl.addStretch(1)
        for name, tip, cb in (
            ("maximize", "Expand the threat network", self._expand_topology),
            ("plus", "Zoom in", self.topology.zoom_in),
            ("minus", "Zoom out", self.topology.zoom_out),
            ("refresh", "Reset view", self.topology.reset_zoom),
        ):
            b = IconButton(name, tip=tip)
            b.setStyleSheet(
                "IconButton { background: #FFFFFF; border: 1px solid #E5E7EB;"
                " border-radius: 10px; }"
                "IconButton:hover { border: 1px solid #FCA5A5; }")
            b.clicked.connect(lambda _c=False, fn=cb: fn())
            rl.addWidget(b, 0, Qt.AlignmentFlag.AlignHCenter)
        rl.addStretch(1)
        br.addWidget(rail, 0)
        hl.addWidget(body_row, 1)

        # legend rows
        self.type_chips_lay = QHBoxLayout()
        self.type_chips_lay.setSpacing(8)
        self.type_chips_lay.addStretch(1)
        self.type_chips: dict[str, TypeChip] = {}
        for key, short, full, color in TYPE_GROUPS:
            chip = TypeChip(key, short, color, 0, full_name=full)
            chip.toggled.connect(self._toggle_type)
            self.type_chips[key] = chip
            self.type_chips_lay.addWidget(chip, 0, Qt.AlignmentFlag.AlignCenter)
        self.type_chips_lay.addStretch(1)
        hl.addLayout(self.type_chips_lay)

        self.sev_chips_lay = QHBoxLayout()
        self.sev_chips_lay.setSpacing(8)
        self.sev_chips_lay.addStretch(1)
        self.sev_chip_widgets: dict[str, SeverityChip] = {}
        for key in ("critical", "high", "medium", "low"):
            chip = SeverityChip(SEV_COLORS[key], f"{SEV_LABELS[key]} (0)")
            self.sev_chip_widgets[key] = chip
            self.sev_chips_lay.addWidget(chip, 0, Qt.AlignmentFlag.AlignCenter)
        self.sev_chips_lay.addStretch(1)
        hl.addLayout(self.sev_chips_lay)
        return hero

    def _build_right_column(self) -> QWidget:
        col = QWidget()
        cl = QVBoxLayout(col)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(14)
        col.setFixedWidth(280)

        # threat intelligence overview
        card = Card()
        card.layout().addWidget(_card_header("Threat Intelligence", "shield",
                                             theme.COLORS["critical"]))
        big = QHBoxLayout()
        big.setSpacing(6)
        self.overview_total = label("0", "BigNumber", wordwrap=False)
        big.addWidget(self.overview_total)
        big.addStretch(1)
        self.overview_delta = QLabel("")
        self.overview_delta.setStyleSheet(
            f"color: {theme.COLORS['critical']}; font-size: 12px; font-weight: 900;"
            " background: transparent;")
        big.addWidget(self.overview_delta)
        card.layout().addLayout(big)
        cap = label("Total tracked indicators", "Subtitle", wordwrap=False)
        cap.setStyleSheet("font-size: 11.5px; color: #64748B;")
        card.layout().addWidget(cap)
        card.layout().addSpacing(4)
        self._sev_rows: dict[str, QFrame] = {}
        for key, icon_name in (("critical", "zap"), ("high", "alert"),
                               ("medium", "target"), ("low", "eye")):
            row = QFrame()
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            row.setStyleSheet(
                "QFrame { background: transparent; border-radius: 8px; }"
                f"QFrame:hover {{ background: {theme.COLORS['hover']}; }}")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(6, 5, 6, 5)
            rl.setSpacing(9)
            ic = QLabel()
            ic.setPixmap(icon(icon_name, SEV_COLORS[key], 13).pixmap(13, 13))
            ic.setFixedSize(24, 24)
            ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ic.setStyleSheet(
                f"background: {theme.rgba_hex(SEV_COLORS[key], 0.10)};"
                " border-radius: 7px;")
            rl.addWidget(ic)
            rl.addWidget(label(SEV_LABELS[key] + " Indicators", "", wordwrap=False), 1)
            count = QLabel("0")
            count.setStyleSheet(
                "font-size: 12.5px; font-weight: 900; color: #111827; background: transparent;")
            rl.addWidget(count)
            ch = QLabel()
            ch.setPixmap(icon("chevron-right", "#C3CBD6", 13).pixmap(13, 13))
            ch.setStyleSheet("background: transparent;")
            rl.addWidget(ch)
            row._count_lbl = count
            row.mouseReleaseEvent = lambda _e: self._goto_threat_intel()
            self._sev_rows[key] = row
            card.layout().addWidget(row)
        cl.addWidget(card)

        # top threat indicators
        card2 = Card()
        card2.layout().addWidget(_card_header("Top Threat Indicators", "target",
                                              "#F97316"))
        self.top_panel = TopIndicatorPanel()
        self.top_panel.indicator_activated.connect(self._open_indicator)
        card2.layout().addWidget(self.top_panel, 1)
        cl.addWidget(card2, 1)
        return col

    # ---------------------------------------------------------------- data
    def _on_range_changed(self, days: int) -> None:
        self._range_days = days
        self.refresh()

    def refresh(self) -> None:
        hub = self.hub()
        stats = hub.repo.stats()
        demo = hub.demo_mode
        demo_kw = demo or None

        # ---- hero topology ------------------------------------------------
        inds = hub.repo.search_indicators(limit=48, demo=demo_kw, order="risk")
        nodes = [{"id": i["id"], "value": i["value"], "type": i["type"],
                  "severity": i.get("severity", "info"),
                  "risk_score": i.get("risk_score", 0)} for i in inds]
        self._topology_nodes = nodes
        self.topology.set_nodes(nodes)

        type_dist = hub.repo.type_distribution(demo_kw)
        ip_count = type_dist.get("ip", 0) + type_dist.get("ipv6", 0)
        chip_counts = {"ip": ip_count, "domain": type_dist.get("domain", 0),
                       "url": type_dist.get("url", 0), "hash": type_dist.get("hash", 0)}
        for key, chip in self.type_chips.items():
            chip.set_count(chip_counts.get(key, 0))

        sev_dist = hub.repo.severity_distribution()
        for key, chip in self.sev_chip_widgets.items():
            chip.set_text(f"{SEV_LABELS[key]} ({sev_dist.get(key, 0)})")

        # ---- ticker ---------------------------------------------------------
        self._fill_ticker(hub, stats, sev_dist)

        # ---- left column ----------------------------------------------------
        self.status_total.setText(f"{stats['total']:,}")
        segs = [(k, sev_dist.get(k, 0), SEV_COLORS[k])
                for k in ("critical", "high", "medium", "low", "info")
                if sev_dist.get(k, 0) > 0]
        self.sev_bar.set_segments(segs)
        self._fill_status_legend(sev_dist)

        countries = hub.repo.top_field("country", 5, demo=demo_kw)
        if countries:
            self.countries_bars.show()
            self.countries_hint.hide()
            self.countries_bars.set_data(
                [(c["key"], c["count"]) for c in countries])
        else:
            self.countries_bars.hide()
            self.countries_hint.show()

        avg_conf = round((stats.get("avg_confidence") or 0) * 100)
        rel = stats.get("relationships", 0)
        camps = stats.get("campaigns", 0)
        self.carousel.set_slides([
            {"title": "Detection Confidence",
             "value": f"{avg_conf}%",
             "delta": "avg across corpus",
             "caption": "Mean provider confidence for every tracked indicator.",
             "accent": theme.COLORS["primary"]},
            {"title": "Infrastructure Links",
             "value": f"{rel:,}",
             "delta": "derived",
             "caption": "Relationships extracted across the indicator graph.",
             "accent": "#8B5CF6"},
            {"title": "Campaigns Tracked",
             "value": f"{camps:,}",
             "delta": "clustered",
             "caption": "Coordinated threat campaigns under observation.",
             "accent": "#F59E0B"},
        ])

        self.nav_invest._value_lbl.setText(f"{stats['investigations']:,}")
        self.nav_campaigns._value_lbl.setText(f"{camps:,}")
        reports = len(hub.repo.list_reports())
        self.nav_reports._value_lbl.setText(f"{reports:,}")

        # ---- right column ---------------------------------------------------
        self.overview_total.setText(f"{stats['total']:,}")
        crit = sev_dist.get("critical", 0)
        high = sev_dist.get("high", 0)
        self.overview_delta.setText(f"▲ {crit + high} high-risk" if crit + high else "")
        for key in ("critical", "high", "medium", "low"):
            row = self._sev_rows[key]
            row._count_lbl.setText(f"{sev_dist.get(key, 0):,}")

        # ---- 3D command gauges ----------------------------------------------
        total_i = stats["total"] or 0
        avg_risk = stats.get("avg_risk", 0) or 0
        self.gauge_threat.set_fraction(avg_risk / 100.0,
                                       caption=f"avg risk {avg_risk:g}")
        self.gauge_conf.set_fraction(stats.get("avg_confidence", 0) or 0,
                                     caption="provider avg")
        exposure = (crit + high) / total_i if total_i else 0.0
        self.gauge_exposure.set_fraction(exposure,
                                         caption=f"{round(exposure * 100)}% of corpus")
        types_present = sum(1 for k in ("ip", "ipv6", "domain", "url", "hash")
                            if (type_dist.get(k, 0) or 0) > 0)
        coverage = types_present / 5
        self.gauge_integrity.set_fraction(coverage,
                                          caption=f"{types_present}/5 types tracked")

        ip_rows = hub.repo.search_indicators(type_="ip", limit=9, demo=demo_kw,
                                             days=self._range_days, order="risk")
        dom_rows = hub.repo.search_indicators(type_="domain", limit=6, demo=demo_kw,
                                              days=self._range_days, order="risk")
        url_rows = hub.repo.search_indicators(type_="url", limit=6, demo=demo_kw,
                                              days=self._range_days, order="risk")
        merged = sorted(dom_rows + url_rows,
                        key=lambda r: -r.get("risk_score", 0))[:9]
        self.top_panel.set_rows(ip_rows, merged)

        # ---- bottom row ------------------------------------------------------
        points = hub.repo.activity_timeline(max(1, self._range_days), demo=demo_kw)
        self.timeline_title.setText(f"Threat Activity — {_range_label_for(self._range_days)}")
        self._replace_widget(self.timeline_host, lambda parent: timeline_chart(
            points, min_height=200, parent=parent))
        self.donut.set_data(sev_dist)

    # ------------------------------------------------------------ helpers
    def _fill_status_legend(self, sev: dict) -> None:
        lay = self._status_legend_lay
        while lay.count():
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        entries = [(k, f"{sev.get(k, 0)} {SEV_LABELS[k]}")
                   for k in ("critical", "high", "medium", "low", "info")
                   if sev.get(k, 0) > 0]
        for idx, (k, text) in enumerate(entries):
            cell = QWidget()
            cell_lay = QHBoxLayout(cell)
            cell_lay.setContentsMargins(0, 0, 0, 0)
            cell_lay.setSpacing(6)
            dot = QLabel()
            dot.setFixedSize(9, 9)
            dot.setStyleSheet(
                f"background: {SEV_COLORS[k]}; border-radius: 5px;")
            cell_lay.addWidget(dot)
            t = label(text, "", wordwrap=False)
            t.setStyleSheet("font-size: 11px; font-weight: 700; color: #475569;")
            cell_lay.addWidget(t)
            cell_lay.addStretch(1)
            lay.addWidget(cell, idx // 2, idx % 2)

    def _fill_ticker(self, hub: ServiceHub, stats: dict, sev: dict) -> None:
        alerts: list[dict] = []
        for ev in hub.repo.recent_events(12):
            level = ("critical" if ev["severity"] == "critical"
                     else "major" if ev["severity"] == "warning" else "minor")
            msg = ev["message"]
            if len(msg) > 92:
                msg = msg[:89] + "…"
            alerts.append({"level": level,
                           "text": f"{msg}  ·  {relative_time(ev['ts'])}"})
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        if crit:
            alerts.append({"level": "critical",
                           "text": f"{crit} critical indicators on record — "
                                   "review the global threat network"})
        if high:
            alerts.append({"level": "major",
                           "text": f"{high} high-risk indicators require assessment"})
        if not alerts:
            alerts.append({"level": "minor",
                           "text": "No intelligence alerts yet — run an investigation"})
        self.ticker.set_alerts(alerts[:10])

    def _replace_widget(self, host: QWidget, factory) -> None:
        lay = host.layout()
        while lay.count():
            item = lay.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        child = factory(host)
        lay.addWidget(child)

    # ------------------------------------------------------- interactions
    def _navigate(self, key: str) -> None:
        win = self.window()
        if hasattr(win, "navigate"):
            win.navigate(key)

    def _goto_threat_intel(self) -> None:
        self._navigate("threat_intelligence")

    def _toggle_type(self, key: str, visible: bool) -> None:
        self.topology.set_type_visible(key, visible)

    def _search_indicator(self) -> None:
        q = self.hero_search.text().strip()
        if not q:
            return
        match = next((n for n in self._topology_nodes
                      if q.lower() in n["value"].lower()), None)
        if match:
            self.topology.focus_value(match["value"])

    def _open_indicator(self, ind: dict) -> None:
        from ..dialogs.indicator_detail import IndicatorDetailDialog

        if ind.get("id"):
            IndicatorDetailDialog(self.window(), ind["id"]).exec()

    def _expand_topology(self) -> None:
        dlg = QDialog(self.window())
        dlg.setWindowTitle("Global Threat Network — Expanded View")
        dlg.resize(1280, 840)
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(12, 12, 12, 12)
        topo = ThreatTopologyWidget()
        topo.set_nodes(getattr(self, "_topology_nodes", []))
        lay.addWidget(topo, 1)
        hint = label("Hover a node to inspect it · click a node to open the "
                     "full indicator dossier", "Muted")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(hint)
        dlg.exec()


def _range_label_for(days: int) -> str:
    return {1: "last 24 hours", 7: "last 7 days", 30: "last 30 days"}.get(
        days, f"last {days} days")
