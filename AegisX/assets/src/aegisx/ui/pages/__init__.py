"""AegisX page registry — the single source of page definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .analytics import AnalyticsPage
from .about import AboutPage
from .base_page import PageBase
from .campaigns import CampaignIntelligencePage
from .correlation import CorrelationPage
from .dashboard import DashboardPage
from .domain_intelligence import DomainIntelligencePage
from .global_map import GlobalMapPage
from .infrastructure import InfrastructurePage
from .investigations import InvestigationsPage
from .ip_investigation import IPInvestigationPage
from .reports import ReportsPage
from .settings import SettingsPage
from .sources import SourcesPage
from .threat_intelligence import ThreatIntelligencePage


@dataclass
class PageSpec:
    key: str
    title: str
    factory: Callable[[], PageBase]


PAGE_SPECS: list[PageSpec] = [
    PageSpec("dashboard", "Dashboard", DashboardPage),
    PageSpec("global_map", "Global Threat Map", GlobalMapPage),
    PageSpec("threat_intelligence", "Threat Intelligence", ThreatIntelligencePage),
    PageSpec("ip_investigation", "IP Investigation", IPInvestigationPage),
    PageSpec("domain_intelligence", "Domain Intelligence", DomainIntelligencePage),
    PageSpec("infrastructure", "Infrastructure Analysis", InfrastructurePage),
    PageSpec("correlation", "Threat Correlation", CorrelationPage),
    PageSpec("campaigns", "Campaign Intelligence", CampaignIntelligencePage),
    PageSpec("analytics", "Threat Analytics", AnalyticsPage),
    PageSpec("investigations", "Investigation Workspace", InvestigationsPage),
    PageSpec("sources", "Intelligence Sources", SourcesPage),
    PageSpec("reports", "Reports", ReportsPage),
    PageSpec("settings", "Settings", SettingsPage),
    PageSpec("about", "About AegisX", AboutPage),
]

__all__ = ["PAGE_SPECS", "PageSpec", "PageBase"]
