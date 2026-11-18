"""
AegisX — Infrastructure Analysis page.

ASN-centric infrastructure views: top hosting countries, ASN table,
infrastructure clusters and an interactive network graph per ASN.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ...visualization.charts import bar_chart
from ...visualization.graph_view import GraphView
from ..components import (
    Badge,
    Card,
    DataTable,
    GhostButton,
    label,
)
from .base_page import PageBase


class InfrastructurePage(PageBase):
    title = "Infrastructure Analysis"
    subtitle = "Hosting patterns, ASN concentration and shared-infrastructure clusters."
    page_key = "infrastructure"

    def build(self) -> None:
        self.maybe_demo_banner()

        charts_row = QWidget()
        cr = QHBoxLayout(charts_row)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(14)
        card_countries = Card()
        card_countries.layout().addWidget(label("Top Hosting Countries", "H3"))
        self.countries_host = QWidget()
        self.countries_lay = QVBoxLayout(self.countries_host)
        self.countries_lay.setContentsMargins(0, 0, 0, 0)
        card_countries.layout().addWidget(self.countries_host, 1)
        cr.addWidget(card_countries, 1)

        card_types = Card()
        card_types.layout().addWidget(label("Indicator Type Distribution", "H3"))
        self.types_host = QWidget()
        self.types_lay = QVBoxLayout(self.types_host)
        self.types_lay.setContentsMargins(0, 0, 0, 0)
        card_types.layout().addWidget(self.types_host, 1)
        cr.addWidget(card_types, 1)
        self.body_lay.addWidget(charts_row, 1)

        # ASN table + cluster selector
        mid_row = QWidget()
        mr = QHBoxLayout(mid_row)
        mr.setContentsMargins(0, 0, 0, 0)
        mr.setSpacing(14)
        card_asn = Card()
        card_asn.layout().addWidget(label("Autonomous Systems Observed", "H3"))
        self.asn_table = DataTable(["ASN", "Network", "Country", "Indicators", "Avg risk"])
        self.asn_table.row_double.connect(self._on_asn)
        card_asn.layout().addWidget(self.asn_table, 1)
        mr.addWidget(card_asn, 3)

        card_clusters = Card()
        card_clusters.layout().addWidget(label("Infrastructure Clusters", "H3"))
        self.cluster_combo = QComboBox()
        self.cluster_combo.currentIndexChanged.connect(lambda _i: self._on_cluster())
        card_clusters.layout().addWidget(self.cluster_combo)
        self.cluster_info = label("", "Muted")
        card_clusters.layout().addWidget(self.cluster_info)
        self.cluster_graph = GraphView()
        self.cluster_graph.setMinimumHeight(300)
        card_clusters.layout().addWidget(self.cluster_graph, 1)
        mr.addWidget(card_clusters, 2)
        self.body_lay.addWidget(mid_row, 2)

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        hub = self.hub()
        demo = hub.demo_mode

        # countries bar
        countries = hub.repo.top_field("country", 8, demo=demo or None)
        self._replace(self.countries_lay, bar_chart(
            [c["key"] for c in countries] or ["—"],
            [c["count"] for c in countries] or [0],
            color=theme.COLORS["primary"], label="Indicators"))

        # types bar
        types = hub.repo.type_distribution()
        self._replace(self.types_lay, bar_chart(
            [t.upper() for t in types.keys()] or ["—"],
            list(types.values()) or [0],
            color=theme.COLORS["info"], label="Indicators"))

        # ASN table
        asns = hub.repo.top_field("asn", 20, demo=demo or None)
        rows = []
        for a in asns:
            rows.append([a["key"], a.get("label") or "", "", str(a["count"]), str(a["avg_risk"])])
        self.asn_table.set_rows(rows, asns)

        # clusters
        facets = hub.correlation.facet_analysis()
        clusters = facets["clusters"]
        self.cluster_combo.blockSignals(True)
        self.cluster_combo.clear()
        for i, cl in enumerate(clusters):
            self.cluster_combo.addItem(f"Cluster {i + 1} — {cl['size']} indicators "
                                       f"(risk {cl['avg_risk']})", i)
        self.cluster_combo.blockSignals(False)
        if clusters:
            self._on_cluster()
        else:
            self.cluster_info.setText(
                "No clusters yet — relationships form as indicators are analyzed.")
            self.cluster_graph.clear()
        self.maybe_demo_banner()

    @staticmethod
    def _replace(lay, chart) -> None:
        while lay.count():
            item = lay.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        lay.addWidget(chart)

    def _on_asn(self, asn_row: dict) -> None:
        hub = self.hub()
        asn = asn_row.get("key") or ""
        inds = hub.repo.search_indicators(limit=60)
        members = [i for i in inds if i.get("asn") == asn]
        nodes = [{"id": i["id"], "value": i["value"], "type": i["type"],
                  "severity": i["severity"]} for i in members]
        edges = [{"source": members[0]["id"], "target": m["id"], "kind": "same-asn",
                  "evidence": f"Shared {asn}"} for m in members[1:]]
        self.cluster_graph.set_graph(nodes, edges)
        self.cluster_info.setText(f"Infrastructure of {asn}: {len(members)} indicators")

    def _on_cluster(self) -> None:
        idx = self.cluster_combo.currentData()
        if idx is None:
            return
        hub = self.hub()
        facets = hub.correlation.facet_analysis()
        clusters = facets["clusters"]
        cl = clusters[idx]
        ids = set(cl["member_ids"])
        all_rels = hub.repo.recent_relationships(500)
        nodes = []
        for mid in cl["member_ids"]:
            ind = hub.repo.get_indicator(mid)
            if ind:
                nodes.append({"id": mid, "value": ind["value"], "severity": ind["severity"],
                              "type": ind["type"]})
        edges = [{"source": r["source_id"], "target": r["target_id"], "kind": r["kind"],
                  "evidence": r.get("evidence", "")}
                 for r in all_rels
                 if r["source_id"] in ids and r["target_id"] in ids]
        self.cluster_graph.set_graph(nodes, edges)
        self.cluster_info.setText(
            f"{cl['size']} indicators · dominant tags: {', '.join(cl['dominant_tags']) or '—'} · "
            f"types: {', '.join(cl['types'])}")
