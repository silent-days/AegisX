"""AegisX — campaign detail dialog (timeline, members, ATT&CK, linking)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.services import ServiceHub
from ...styles import theme
from ..components import (
    Badge,
    Card,
    DataTable,
    GhostButton,
    KVWidget,
    PrimaryButton,
    label,
    relative_time,
)
from ..icons import icon


class CampaignDetailDialog(QDialog):
    def __init__(self, parent: QWidget | None, campaign_id: int) -> None:
        super().__init__(parent)
        self.campaign_id = campaign_id
        self.setWindowTitle("Campaign Detail")
        self.setModal(True)
        self.setMinimumSize(860, 600)

        hub = ServiceHub.get()
        camp = hub.repo.get_campaign(campaign_id) or {}
        members = hub.repo.campaign_indicators(campaign_id)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(12)

        head = QHBoxLayout()
        col = QVBoxLayout()
        col.addWidget(label(camp.get("name", "?"), "H2"))
        col.addWidget(label(camp.get("description", ""), "Muted"))
        head.addLayout(col, 1)
        head.addWidget(Badge(camp.get("severity", "info").upper(), camp.get("severity", "info")))
        lay.addLayout(head)

        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(0, 0, 0, 0)
        il.setSpacing(12)

        meta = Card()
        kv = KVWidget()
        kv.set_items([
            ("First seen", relative_time(camp.get("first_seen"))),
            ("Last seen", relative_time(camp.get("last_seen"))),
            ("Confidence", f"{round((camp.get('confidence') or 0) * 100)}%"),
            ("Attribution", camp.get("attribution") or
             "No attribution claimed — evidence insufficient for actor attribution."),
            ("Tags", ", ".join(camp.get("tags") or []) or "—"),
        ])
        meta.layout().addWidget(kv)
        il.addWidget(meta)

        mitre = Card()
        mitre.layout().addWidget(label("MITRE ATT&CK Associations", "H3"))
        from ...core.mitre import describe

        row = QHBoxLayout()
        for tid in camp.get("mitre", [])[:8]:
            name, tactic = describe(tid)
            chip = Badge(f"{tid} · {name}", "primary")
            chip.setToolTip(f"{tactic}")
            row.addWidget(chip)
        row.addStretch(1)
        mitre.layout().addLayout(row)
        if not camp.get("mitre"):
            mitre.layout().addWidget(label("No ATT&CK associations recorded.", "Muted"))
        il.addWidget(mitre)

        tbl_card = Card()
        tbl_card.layout().addWidget(label(f"Associated indicators ({len(members)})", "H3"))
        table = DataTable(["Indicator", "Type", "Severity", "Risk", "Country", "ASN"])
        rows = [[m["value"], m["type"].upper(), m["severity"].upper(),
                 f"{m['risk_score']}/100", m.get("country") or "—", m.get("asn") or "—"]
                for m in members]
        table.set_rows(rows, members)
        tbl_card.layout().addWidget(table, 1)
        il.addWidget(tbl_card, 1)
        il.addStretch(1)
        area.setWidget(inner)
        lay.addWidget(area, 1)

        actions = QHBoxLayout()
        btn_link = PrimaryButton("Link indicator", "link")
        btn_link.clicked.connect(self._link_indicator)
        actions.addWidget(btn_link)
        actions.addStretch(1)
        btn_close = GhostButton("Close")
        btn_close.clicked.connect(self.accept)
        actions.addWidget(btn_close)
        lay.addLayout(actions)

    def _link_indicator(self) -> None:
        from ...ui.dialogs.common import TextDialog

        dlg = TextDialog(self, "Link indicator to campaign",
                         placeholder="IP, domain, URL or hash (must already be analyzed)")
        if not dlg.exec():
            return
        hub = ServiceHub.get()
        ind = hub.repo.get_indicator_by_value(dlg.value())
        if not ind:
            report = hub.engine.lookup(dlg.value())
            ind = hub.repo.get_indicator_by_value(dlg.value()) if report else None
        if ind:
            hub.repo.link_campaign_indicator(self.campaign_id, ind["id"])
            hub.events.publish("campaign.updated", "Indicator linked to campaign",
                               severity="success")
            self.accept()
