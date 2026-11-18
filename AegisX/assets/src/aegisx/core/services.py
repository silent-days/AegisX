"""
AegisX — service hub.

Wires the platform singletons together and owns global settings. Created
once at startup and handed to every page via ``services.get()``.
"""

from __future__ import annotations

import logging
import os

from ..database.repository import Repository
from ..security.keystore import KeyStore
from ..utils.logger import get_logger
from ..utils.paths import database_path
from .correlation_engine import CorrelationEngine
from .event_manager import EventManager
from .intelligence_engine import IntelligenceEngine
from .indicator_manager import IndicatorManager

log = get_logger("aegisx.services")


class Settings:
    """Typed access to application settings (DB-backed with env overrides)."""

    DEFAULTS = {
        "demo_mode": "0",            # real provider-backed mode by default
        "animations": "1",
        "auto_refresh_sec": "60",
        "cache_ttl_hours": "6",
        "log_level": "INFO",
        "analyst_name": "Security Researcher",
        "default_depth": "1",
        "activity_days": "30",
    }

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def get(self, key: str) -> str:
        env = os.environ.get(f"AEGISX_{key.upper()}")
        if env:
            return env
        return self.repo.get_setting(key, self.DEFAULTS.get(key, ""))

    def set(self, key: str, value: str) -> None:
        self.repo.set_setting(key, str(value))
        self.repo.add_event("settings", f"Setting '{key}' updated")

    def flag(self, key: str) -> bool:
        return self.get(key).lower() in ("1", "true", "yes", "on")


class ServiceHub:
    _instance: "ServiceHub | None" = None

    def __init__(self) -> None:
        self.repo = Repository(database_path())
        self.keystore = KeyStore()
        self.events = EventManager()
        self.settings = Settings(self.repo)
        self.indicators = IndicatorManager(self.repo)
        self.correlation = CorrelationEngine(self.repo)
        self.engine = IntelligenceEngine(
            self.repo, self.keystore, self.events,
            # Never synthesize threat intelligence in the production desktop app.
            demo_mode=False,
        )

    # ------------------------------------------------------------- lifecycle
    @classmethod
    def create(cls) -> "ServiceHub":
        cls._instance = ServiceHub()
        return cls._instance

    @classmethod
    def get(cls) -> "ServiceHub":
        assert cls._instance is not None, "ServiceHub not initialised"
        return cls._instance

    @property
    def demo_mode(self) -> bool:
        return self.engine.demo_mode

    def set_demo_mode(self, enabled: bool) -> None:
        self.engine.demo_mode = enabled
        self.settings.set("demo_mode", "1" if enabled else "0")
        self.events.publish(
            "mode.changed",
            "Demonstration mode enabled — sample data will be shown" if enabled
            else "Live mode enabled — configured providers will be queried",
            severity="info",
        )
        if not enabled and not self.keystore.configured_providers():
            self.events.publish(
                "mode.info",
                "Live mode: keyless community sources (Spamhaus DBL/ZEN, Tor, "
                "DoH, crt.sh, OpenGeo) are querying real intelligence. API-key "
                "feeds can be added on top in Intelligence Sources.",
                severity="info",
            )


def init_services() -> ServiceHub:
    return ServiceHub.create()
