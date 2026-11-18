"""
AegisX — Campaign Intelligence page.

Campaign cards with severity/confidence, indicator membership, MITRE
associations, timelines and honest attribution handling (no attribution
claimed without provider evidence).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...styles import theme
from ...utils.validators import sha256_of
from ..components import (
    Badge,
    Banner,
    Card,
    DangerButton,
    EmptyState,
    GhostButton,
    PrimaryButton,
    label,
    relative_time,
)
from ..icons import icon
from .base_page import PageBase


class CampaignIntelligencePage(PageBase):
    title = "Campaign Intelligence"
    subtitle = "Clustered threat campaigns with evidence-backed indicator membership."
    page_key = "campaigns"

    def build(self) -> None:
        self.maybe_demo_banner()

        actions = QWidget()
        al = QHBoxLayout(actions)
        al.setContentsMargins(0, 0, 0, 0)
        al.addStretch(1)
        btn_new = PrimaryButton("New campaign", "plus")
        btn_new.clicked.connect(self._new_campaign)
        al.addWidget(btn_new)
        self.body_lay.addWidget(actions)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.grid_host = QWidget()
        self.grid = QGridLayout(self.grid_host)
        self.grid.setSpacing(14)
        self.scroll.setWidget(self.grid_host)
        self.body_lay.addWidget(self.scroll, 1)

        self.empty = EmptyState(
            "No campaigns yet",
            "Campaigns group related infrastructure. Analyze indicators and cluster "
            "them, or create a campaign and link indicators manually.",
            icon_name="flag",
            action=PrimaryButton("Create first campaign", "plus"),
        )
        self.empty.findChild(QFrame)  # noop to satisfy linters
        self._selected_campaign = None

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        hub = self.hub()
        campaigns = hub.repo.list_campaigns()
        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not campaigns:
            self.scroll.hide()
            self.empty.show()
            self.body_lay.addWidget(self.empty)
            return
        self.scroll.show()
        cols = 2
        for i, camp in enumerate(campaigns):
            self.grid.addWidget(self._campaign_card(camp), i // cols, i % cols)
        for j in range(cols):
            self.grid.setColumnStretch(j, 1)
        self.grid.setRowStretch(self.grid.rowCount(), 1)
        self.maybe_demo_banner()

    def _campaign_card(self, camp: dict) -> QWidget:
        card = Card(interactive=True)
        head = QHBoxLayout()
        icon_lbl = QLabel()
        icon_lbl.setPixmap(icon("flag", theme.SEVERITY_COLORS.get(camp["severity"], "#64748B"),
                                20).pixmap(20, 20))
        head.addWidget(icon_lbl)
        head.addWidget(label(camp["name"], "H2"), 1)
        head.addWidget(Badge(camp["severity"].upper(), camp["severity"]))
        card.layout().addLayout(head)

        card.layout().addWidget(label(camp["description"] or "No description.", "Subtitle"))

        meta = QHBoxLayout()
        meta.addWidget(label(f"{camp['indicator_count']} indicators", "", wordwrap=False))
        meta.addWidget(label("·", "Muted", wordwrap=False))
        conf = round(camp["confidence"] * 100)
        conf_lbl = label(f"confidence {conf}%", "", wordwrap=False)
        meta.addWidget(conf_lbl)
        meta.addWidget(label("·", "Muted", wordwrap=False))
        meta.addWidget(label(f"updated {relative_time(camp.get('last_seen'))}", "Muted", wordwrap=False))
        meta.addStretch(1)
        card.layout().addLayout(meta)

        # attribution line — honest handling
        if camp.get("attribution"):
            attr = label(
                f"Community attribution: {camp['attribution']} "
                f"(confidence {round((camp.get('attribution_confidence') or 0) * 100)}% — "
                "provider claim, not asserted by AegisX)", "Muted")
            card.layout().addWidget(attr)
        else:
            card.layout().addWidget(label(
                "No attribution claimed — evidence insufficient for actor attribution.", "Muted"))

        # tags + mitre
        chips = QHBoxLayout()
        for t in camp.get("tags", [])[:4]:
            chips.addWidget(Badge(t, "info"))
        for m in camp.get("mitre", [])[:4]:
            chips.addWidget(Badge(m, "primary"))
        chips.addStretch(1)
        card.layout().addLayout(chips)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        btn_open = GhostButton("Open", "chevron-right")
        btn_open.clicked.connect(lambda _=False, c=camp: self._open_campaign(c))
        btn_row.addWidget(btn_open)
        btn_del = GhostButton("Delete", "trash")
        btn_del.clicked.connect(lambda _=False, c=camp: self._delete_campaign(c))
        btn_row.addWidget(btn_del)
        card.layout().addLayout(btn_row)
        return card

    # ------------------------------------------------------------- campaign view
    def _open_campaign(self, camp: dict) -> None:
        from ...ui.dialogs.campaign_detail import CampaignDetailDialog

        CampaignDetailDialog(self, camp["id"])

    def _delete_campaign(self, camp: dict) -> None:
        from ..dialogs.common import ConfirmDialog

        dlg = ConfirmDialog(self, "Delete campaign",
                            f"Delete campaign '{camp['name']}'? Linked indicators are kept.",
                            confirm_text="Delete")
        if not dlg.accepted():
            return
        hub = self.hub()
        hub.repo._x("DELETE FROM campaigns WHERE id=?", (camp["id"],))
        hub.events.publish("campaign.deleted", f"Campaign '{camp['name']}' removed",
                           severity="warning")
        self.refresh()

    def _new_campaign(self) -> None:
        from ...ui.dialogs.common import TextDialog

        dlg = TextDialog(self, "New campaign name", placeholder="e.g. Operation Aurora Sample")
        if not dlg.exec():
            return
        hub = self.hub()
        hub.repo.upsert_campaign(dlg.value(),
                                 description="Created manually — link indicators from any page.")
        hub.events.publish("campaign.created", f"Campaign '{dlg.value()}' created",
                           severity="success")
        self.refresh()
