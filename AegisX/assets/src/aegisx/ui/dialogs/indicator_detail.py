"""AegisX — indicator detail dialog (full finding history + actions)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.services import ServiceHub
from ...styles import theme
from ..components import Badge, Card, GhostButton, KVWidget, PrimaryButton, label, relative_time
from ..icons import icon


class IndicatorDetailDialog(QDialog):
    def __init__(self, parent: QWidget | None, indicator_id: int) -> None:
        super().__init__(parent)
        self.indicator_id = indicator_id
        self.setWindowTitle("Indicator Details")
        self.setModal(True)
        self.setMinimumSize(680, 560)

        hub = ServiceHub.get()
        ind = hub.repo.get_indicator(indicator_id) or {}
        findings = hub.repo.findings_for_indicator(indicator_id)
        rels = hub.repo.relationships_for(indicator_id)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(12)

        head = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.addWidget(label(ind.get("value", "?"), "H2"))
        sub = label(
            f"{ind.get('type', '').upper()} · severity {ind.get('severity', '').upper()} · "
            f"risk {ind.get('risk_score', 0)}/100 · confidence {round((ind.get('confidence') or 0) * 100)}%",
            "Muted")
        title_col.addWidget(sub)
        head.addLayout(title_col, 1)
        head.addWidget(Badge(ind.get("severity", "info").upper(), ind.get("severity", "info")))
        lay.addLayout(head)

        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(0, 0, 0, 0)
        il.setSpacing(12)

        ctx = Card()
        kv = KVWidget()
        kv.set_items([
            ("Country", ind.get("country") or "—"),
            ("ASN", ind.get("asn") or "—"),
            ("ASN name", ind.get("asn_name") or "—"),
            ("Tags", ", ".join(ind.get("tags") or []) or "—"),
            ("First seen", relative_time(ind.get("first_seen"))),
            ("Last seen", relative_time(ind.get("last_seen"))),
            ("Status", ind.get("status", "active")),
        ], mono_keys=("ASN",))
        ctx.layout().addWidget(kv)
        il.addWidget(ctx)

        rel_card = Card()
        rel_card.layout().addWidget(label(f"Relationships ({len(rels)})", "H3"))
        for r in rels[:8]:
            other = r["target_value"] if r["source_id"] == indicator_id else r["source_value"]
            row = QLabel(f"<b style='font-family:monospace'>{other}</b> — {r['kind']} "
                         f"({r['evidence']})")
            row.setWordWrap(True)
            row.setStyleSheet("font-size: 12px; color: #374151; background: transparent;")
            rel_card.layout().addWidget(row)
        if not rels:
            rel_card.layout().addWidget(label("No derived relationships yet.", "Muted"))
        il.addWidget(rel_card)

        f_card = Card()
        f_card.layout().addWidget(label(f"Finding history ({len(findings)})", "H3"))
        for f in findings[:20]:
            box = QLabel(
                f"<b>{f['source']}</b> · {f['severity'].upper()} · "
                f"score {f['score'] if f['score'] is not None else '—'} · "
                f"{relative_time(f['recorded_at'])}<br>{f['summary']}"
            )
            box.setWordWrap(True)
            box.setStyleSheet(
                f"font-size: 12px; color: #374151; background: {theme.COLORS['surface_alt']};"
                f"border-radius: 8px; padding: 8px;")
            f_card.layout().addWidget(box)
        if not findings:
            f_card.layout().addWidget(label("No findings recorded.", "Muted"))
        il.addWidget(f_card)
        il.addStretch(1)
        area.setWidget(inner)
        lay.addWidget(area, 1)

        actions = QHBoxLayout()
        btn_delete = GhostButton("Delete indicator", "trash")
        btn_delete.clicked.connect(self._delete)
        actions.addWidget(btn_delete)
        actions.addStretch(1)
        btn_close = PrimaryButton("Close")
        btn_close.clicked.connect(self.accept)
        actions.addWidget(btn_close)
        lay.addLayout(actions)

    def _delete(self) -> None:
        from ..dialogs.common import ConfirmDialog

        dlg = ConfirmDialog(self, "Delete indicator",
                            "This removes the indicator, its findings and relationships. Continue?",
                            confirm_text="Delete")
        if not dlg.accepted():
            return
        hub = ServiceHub.get()
        hub.repo.delete_indicator(self.indicator_id)
        hub.events.publish("indicator.deleted", "Indicator removed from database",
                           severity="warning")
        self.accept()
