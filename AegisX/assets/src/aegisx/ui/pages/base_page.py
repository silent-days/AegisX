"""
AegisX — page base class + registry.

Every page inherits PageBase which provides: service access, the standard
page header pattern, an async refresh lock and demo-mode banner plumbing.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QScrollArea, QVBoxLayout, QWidget

from ...core.services import ServiceHub
from ..components import Banner, section_header


class PageBase(QWidget):
    """Base class for all main-window pages."""

    title = ""
    subtitle = ""
    page_key = ""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._refreshing = False
        self._root_lay = QVBoxLayout(self)
        self._root_lay.setContentsMargins(28, 24, 28, 24)
        self._root_lay.setSpacing(16)
        self.header = section_header(self.title, self.subtitle)
        self._root_lay.addWidget(self.header)
        self.demo_banner: Banner | None = None
        self._scroll: QScrollArea | None = None
        self.body = QWidget()
        self.body_lay = QVBoxLayout(self.body)
        self.body_lay.setContentsMargins(0, 0, 0, 0)
        self.body_lay.setSpacing(16)
        self._root_lay.addWidget(self.body, 1)
        self.build()
        self.refresh()

    # ------------------------------------------------------------------ api
    def hub(self) -> ServiceHub:
        return ServiceHub.get()

    @property
    def demo_mode(self) -> bool:
        return ServiceHub.get().demo_mode

    def maybe_demo_banner(self, text: str | None = None) -> None:
        """Show/refresh the demonstration-mode banner when applicable."""
        if self.demo_banner:
            self.body_lay.removeWidget(self.demo_banner)
            self.demo_banner.deleteLater()
            self.demo_banner = None
        if self.demo_mode:
            self.demo_banner = Banner(
                text or "Demonstration mode — showing clearly-labelled sample data "
                "(RFC 5737 test ranges). Configure provider API keys in Settings for live intelligence.",
                "demo",
            )
            self.body_lay.insertWidget(0, self.demo_banner)

    def set_header(self, title: str | None = None, subtitle: str | None = None) -> None:
        """Replace the default header (pages with dynamic subtitles)."""
        idx = self._root_lay.indexOf(self.header)
        if idx >= 0:
            self._root_lay.removeWidget(self.header)
            self.header.deleteLater()
        self.header = section_header(
            title if title is not None else self.title,
            subtitle if subtitle is not None else self.subtitle,
        )
        self._root_lay.insertWidget(0, self.header)

    # ------------------------------------------------------- overridden api
    def build(self) -> None:
        """Construct page widgets. Override."""

    def refresh(self) -> None:
        """Reload data. Override; called on page show and explicit refresh."""
