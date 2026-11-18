"""
AegisX — Threat Correlation page.

Interactive relationship graph builder: pick an indicator, expand by depth
and relationship kind, inspect edge evidence and jump into investigations.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from ...visualization.graph_view import GraphView
from ...workers import TaskManager
from ..components import (
    Badge,
    Card,
    GhostButton,
    KVWidget,
    PrimaryButton,
    Spinner,
    label,
)
from .base_page import PageBase

KINDS = ("same-asn", "resolves-to", "campaign", "shared-tags")


class CorrelationPage(PageBase):
    title = "Threat Correlation"
    subtitle = "Explore evidence-backed relationships between malicious infrastructure."
    page_key = "correlation"

    def build(self) -> None:
        self.maybe_demo_banner()

        # control bar
        bar = Card()
        gl = QGridLayout()
        gl.setSpacing(10)
        gl.addWidget(label("Center indicator", "H3"), 0, 0)
        self.input = QLineEdit()
        self.input.setPlaceholderText("IP or domain, e.g. 192.0.2.44")
        gl.addWidget(self.input, 0, 1)
        self.depth_combo = QComboBox()
        self.depth_combo.addItems(["Depth: 1 hop", "Depth: 2 hops"])
        gl.addWidget(self.depth_combo, 0, 2)

        self.kind_checks: dict[str, QCheckBox] = {}
        for i, kind in enumerate(KINDS):
            cb = QCheckBox(kind)
            cb.setChecked(True)
            self.kind_checks[kind] = cb
            gl.addWidget(cb, 1, i)
        self.btn_build = PrimaryButton("Build graph", "share")
        self.btn_build.clicked.connect(self._build)
        gl.addWidget(self.btn_build, 0, 3)
        self.spinner = Spinner(20)
        self.spinner.hide()
        gl.addWidget(self.spinner, 1, 4)
        bar.layout().addLayout(gl)
        self.body_lay.addWidget(bar)

        # graph + evidence
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(14)
        card_graph = Card()
        self.graph = GraphView()
        self.graph.node_selected.connect(self._on_node)
        card_graph.layout().addWidget(self.graph, 1)
        card_graph.setMinimumHeight(460)
        rl.addWidget(card_graph, 4)

        side = Card()
        side.layout().addWidget(label("Evidence Panel", "H3"))
        self.evidence = KVWidget()
        side.layout().addWidget(self.evidence, 1)
        self.stats_lbl = label("", "Muted")
        side.layout().addWidget(self.stats_lbl)
        self.btn_add = PrimaryButton("Add to investigation", "plus")
        self.btn_add.setEnabled(False)
        self.btn_add.clicked.connect(self._add_to_inv)
        side.layout().addWidget(self.btn_add)
        rl.addWidget(side, 2)
        self.body_lay.addWidget(row, 1)

        self._selected: dict | None = None
        self._result: dict | None = None

    # ----------------------------------------------------------------- build
    def _build(self) -> None:
        value = self.input.text().strip()
        if not value:
            return
        hub = self.hub()
        ind = hub.repo.get_indicator_by_value(value)
        if not ind:
            # analyze on demand (async)
            self.spinner.start()
            TaskManager.get().submit(
                hub.engine.lookup, value,
                description="correlation-lookup",
                on_done=self._after_lookup, on_error=self._after_lookup_err,
            )
            return
        self._render_graph(ind["id"])

    def _after_lookup(self, report) -> None:
        self.spinner.stop()
        if report:
            self._render_graph(report["indicator"]["id"])
        else:
            self.evidence.set_items([("Error", "Invalid indicator — nothing to correlate.")])

    def _after_lookup_err(self, err: str) -> None:
        self.spinner.stop()
        self.evidence.set_items([("Error", err[:200])])

    def _render_graph(self, center_id: int) -> None:
        hub = self.hub()
        depth = self.depth_combo.currentIndex() + 1
        kinds = {k for k, cb in self.kind_checks.items() if cb.isChecked()}
        graph = hub.correlation.build_graph(center_id, depth=depth, kinds=kinds)
        self._result = graph
        self.graph.set_graph(
            [{"id": n["id"], "value": n["value"], "severity": n.get("severity", "info"),
              "type": n.get("type", "")} for n in graph["nodes"]],
            graph["edges"],
        )
        self.stats_lbl.setText(
            f"{len(graph['nodes'])} nodes · {len(graph['edges'])} evidence-backed relationships")
        self.btn_add.setEnabled(bool(graph["nodes"]))

    # ---------------------------------------------------------------- events
    def _on_node(self, node: dict) -> None:
        self._selected = node
        hub = self.hub()
        ind = hub.repo.get_indicator(node.get("id"))
        if not ind:
            return
        rels = hub.repo.relationships_for(ind["id"])
        items = [
            ("Indicator", ind["value"]),
            ("Type", ind["type"].upper()),
            ("Severity", ind["severity"].upper()),
            ("Risk", f"{ind['risk_score']}/100"),
            ("Country / ASN", f"{ind.get('country') or '—'} · {ind.get('asn') or '—'}"),
            ("Relationships", str(len(rels))),
        ]
        for r in rels[:4]:
            other = r["target_value"] if r["source_id"] == ind["id"] else r["source_value"]
            items.append(("Linked", f"{other} · {r['kind']}"))
        self.evidence.set_items(items, mono_keys=("Indicator",))
        self.btn_add.setEnabled(True)

    def _add_to_inv(self) -> None:
        if not self._selected:
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
        hub.repo.add_investigation_item(inv_id, self._selected["id"])
        hub.events.publish("investigation.updated", "Indicator added from correlation graph",
                           severity="success")

    def refresh(self) -> None:
        self.maybe_demo_banner()
