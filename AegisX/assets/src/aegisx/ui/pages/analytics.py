"""
AegisX — Threat Analytics page.

Analytical charts over the tracked corpus: activity timeline, severity and
confidence distributions, source contribution and ATT&CK technique
frequency. Export any chart as PNG.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.mitre import describe
from ...styles import theme
from ...visualization.charts import bar_chart, timeline_chart
from ..components import (
    Card,
    GhostButton,
    label,
)
from .base_page import PageBase


class AnalyticsPage(PageBase):
    title = "Threat Analytics"
    subtitle = "Cross-cutting analytics over every tracked indicator and source."
    page_key = "analytics"

    def build(self) -> None:
        self.maybe_demo_banner()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        grid_host = QWidget()
        self.grid = QGridLayout(grid_host)
        self.grid.setSpacing(14)
        scroll.setWidget(grid_host)
        self.body_lay.addWidget(scroll, 1)

        self._charts: dict[str, QWidget] = {}
        specs = [
            ("timeline", "Threat Activity Timeline", 0, 0, 2),
            ("severity", "Severity Distribution", 1, 0, 1),
            ("sources", "Source Contribution", 1, 1, 1),
            ("countries", "Top Countries", 2, 0, 1),
            ("asns", "Top Autonomous Systems", 2, 1, 1),
            ("confidence", "Confidence Distribution", 3, 0, 1),
            ("mitre", "ATT&CK Technique Frequency", 3, 1, 1),
        ]
        for key, title, r, c, span in specs:
            card = Card()
            head = QHBoxLayout()
            head.addWidget(label(title, "H3"))
            head.addStretch(1)
            export_btn = GhostButton("PNG", "download")
            export_btn.setToolTip("Export chart as PNG")
            export_btn.clicked.connect(lambda _=False, k=key, t=title: self._export_chart(k, t))
            head.addWidget(export_btn)
            card.layout().addLayout(head)
            host = QWidget()
            host.setMinimumHeight(230)
            self._charts[key] = host
            card.layout().addWidget(host, 1)
            self.grid.addWidget(card, r, c, 1, span)
        for c in range(2):
            self.grid.setColumnStretch(c, 1)

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        hub = self.hub()
        demo = hub.demo_mode or None

        timeline = hub.repo.activity_timeline(30, demo=demo)
        self._swap("timeline", timeline_chart(timeline, min_height=240))

        sev = hub.repo.severity_distribution()
        order = ("critical", "high", "medium", "low", "info")
        self._swap("severity", bar_chart(
            [s.capitalize() for s in order],
            [sev.get(s, 0) for s in order],
            color=theme.COLORS["primary"], min_height=240))

        contrib = hub.repo.source_contribution()
        self._swap("sources", bar_chart(
            [c["source"] for c in contrib] or ["—"],
            [c["count"] for c in contrib] or [0],
            color=theme.COLORS["info"], min_height=240))

        countries = hub.repo.top_field("country", 8, demo=demo)
        self._swap("countries", bar_chart(
            [c["key"] for c in countries] or ["—"],
            [c["count"] for c in countries] or [0],
            color=theme.COLORS["sev_medium"], min_height=240))

        asns = hub.repo.top_field("asn", 8, demo=demo)
        self._swap("asns", bar_chart(
            [a["key"] for a in asns] or ["—"],
            [a["count"] for a in asns] or [0],
            color=theme.COLORS["success"], horizontal=True, min_height=240))

        hist = hub.repo.confidence_histogram(demo=demo)
        self._swap("confidence", bar_chart(
            [h["bucket"] for h in hist],
            [h["count"] for h in hist],
            color=theme.COLORS["sev_info"], min_height=240))

        # MITRE frequency from campaign mapping + indicator tags
        counts: dict[str, int] = {}
        for camp in hub.repo.list_campaigns():
            for tid in camp.get("mitre", []):
                counts[tid] = counts.get(tid, 0) + 1
        tags_seen: list[str] = []
        for ind in hub.repo.search_indicators(limit=400):
            tags_seen += ind.get("tags") or []
        from ...core.mitre import techniques_for_tags

        for tid in techniques_for_tags(tags_seen):
            counts[tid] = counts.get(tid, 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])[:8]
        self._swap("mitre", bar_chart(
            [f"{tid}" for tid, _ in top] or ["—"],
            [n for _, n in top] or [0],
            color=theme.COLORS["sev_critical"], horizontal=True, min_height=240))
        self.maybe_demo_banner()

    def _swap(self, key: str, chart: QWidget) -> None:
        host = self._charts[key]
        lay = host.layout()
        if lay is None:
            from PySide6.QtWidgets import QVBoxLayout

            lay = QVBoxLayout(host)
            lay.setContentsMargins(0, 0, 0, 0)
        while lay.count():
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        lay.addWidget(chart)

    def _export_chart(self, key: str, title: str) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export chart PNG",
                                              f"aegisx-{key}.png", "PNG images (*.png)")
        if not path:
            return
        host = self._charts[key]
        pix = host.grab()
        if pix.save(path, "PNG"):
            QMessageBox.information(self, "Export complete", f"'{title}' saved to {path}")
        else:
            QMessageBox.critical(self, "Export failed", "Could not write the image file.")
