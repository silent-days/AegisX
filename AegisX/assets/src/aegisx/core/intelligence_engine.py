"""
AegisX — intelligence engine.

Orchestrates the full analysis pipeline for a single indicator:

    normalize -> check cache -> query providers (concurrently)
    -> normalize findings -> evidence-based risk scoring
    -> persistence -> relationship derivation -> event publication

In demonstration mode the engine synthesizes clearly-labelled, deterministic
sample intelligence (seeded per indicator) using RFC 5737 documentation
ranges — it never presents fabricated data as live intelligence.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import random
from datetime import datetime, timedelta, timezone

from ..database.repository import Repository, iso, utcnow
from ..providers import PROVIDER_CLASSES
from ..security.keystore import KeyStore
from .correlation_engine import CorrelationEngine
from .event_manager import EventManager
from .indicator_manager import IndicatorManager
from .mitre import describe, techniques_for_tags
from .risk_engine import score_indicator

log = logging.getLogger("aegisx.engine")


class IntelligenceEngine:
    def __init__(self, repo: Repository, keystore: KeyStore, events: EventManager,
                 demo_mode: bool = False) -> None:
        self.repo = repo
        self.keystore = keystore
        self.events = events
        self.demo_mode = demo_mode
        self.indicators = IndicatorManager(repo)
        self.correlation = CorrelationEngine(repo)
        self.providers = {name: cls(keystore, repo) for name, cls in PROVIDER_CLASSES.items()}

    # ------------------------------------------------------------ providers
    def provider(self, name: str):
        return self.providers.get(name.lower())

    def provider_states(self) -> dict[str, dict]:
        states = {}
        for name, p in self.providers.items():
            states[name] = {
                "display_name": p.display_name,
                "configured": p.is_configured(),
                "requires_key": p.requires_key,
                "description": p.description,
                "capabilities": list(p.capabilities),
                "docs_url": p.docs_url,
                "ttl": p.default_ttl,
                "rate_delay": p.min_interval,
            }
        return states

    # --------------------------------------------------------------- lookup
    def lookup(self, raw: str, *, force_refresh: bool = False,
               progress_cb=None) -> dict | None:
        """
        Full pipeline for one indicator. Returns the report dict or None when
        the input is not a valid indicator.
        """
        norm = self.indicators.normalize(raw)
        if not norm:
            return None

        def step(msg, pct=None):
            if progress_cb:
                progress_cb(msg, pct)

        demo = self.demo_mode
        step(f"Normalizing {norm.value}", 5)
        indicator_id = self.indicators.ensure_indicator(norm, demo=demo)

        findings: list[dict] = []

        if demo:
            step("Querying demonstration intelligence feed", 25)
            findings = self._demo_findings(norm)
            for f in findings:
                self.indicators.record_finding(indicator_id, f, demo=True)
        else:
            active = [p for p in self.providers.values() if p.is_configured()]
            if not active:
                self.events.publish(
                    "lookup.no_sources",
                    "No intelligence providers configured — configure API keys in Settings.",
                    severity="warning",
                )
            total = max(1, len(active))
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, max(1, len(active)))) as pool:
                futures = {pool.submit(self._query_provider, p, norm, force_refresh): p for p in active}
                done = 0
                for fut in concurrent.futures.as_completed(futures):
                    provider = futures[fut]
                    done += 1
                    step(f"Processing {provider.display_name}", 20 + int(70 * done / total))
                    try:
                        pf = fut.result()
                    except Exception as e:  # noqa: BLE001
                        log.warning("Provider %s failed: %s", provider.display_name, e)
                        self.repo.set_source_state(provider.name, "error", error=str(e)[:300])
                        self.events.publish(
                            "source.error",
                            f"{provider.display_name}: {str(e)[:120]}",
                            severity="warning", provider=provider.name,
                        )
                        continue
                    for f in pf:
                        self.indicators.record_finding(indicator_id, f)
                    findings.extend(pf)

        step("Scoring evidence", 80)
        result = score_indicator(findings, indicator_meta={"type": norm.type})
        self.indicators.finalize_scoring(indicator_id, result)

        step("Correlating infrastructure", 90)
        derived = self.correlation.derive_for_indicator(indicator_id)

        report = self._build_report(indicator_id, norm, findings, result, derived)
        step("Complete", 100)

        self.events.publish(
            "lookup.completed",
            f"Analysis complete for {norm.value} — risk {result.score}/100 ({result.severity})",
            severity=result.severity if result.severity in ("info", "low", "medium", "high", "critical") else "info",
            value=norm.value, score=result.score,
        )
        self.repo.add_event("lookup", f"Analyzed {norm.value} → risk {result.score}/100 ({result.severity})",
                            severity=result.severity, data={"id": indicator_id})
        return report

    def _query_provider(self, provider, norm, force_refresh: bool) -> list[dict]:
        try:
            return provider.lookup(norm, force_refresh=force_refresh)
        finally:
            self.repo.bump_source_counters(provider.name, request=True)

    # -------------------------------------------------------------- report
    def _build_report(self, indicator_id: int, norm, findings, result, derived: int) -> dict:
        ind = self.indicators.get(indicator_id) or {}
        findings = sorted(findings, key=lambda f: -(f.get("score") or 0))
        return {
            "indicator": ind,
            "normalized": norm.to_dict(),
            "findings": findings,
            "risk": result.to_dict(),
            "mitre": [
                {"id": tid, "name": describe(tid)[0], "tactic": describe(tid)[1]}
                for tid in techniques_for_tags(
                    sorted({t for f in findings for t in (f.get("tags") or [])})
                )
            ],
            "relationships_added": derived,
            "sources_queried": [f.get("source") for f in findings],
            "generated_at": iso(),
            "demo": self.demo_mode,
        }

    # ---------------------------------------------------------- demo engine
    DEMO_TAGS_BY_SEVERITY = {
        "critical": ["c2", "botnet", "dga"],
        "high": ["loader", "malware-delivery", "scanner"],
        "medium": ["scanning", "spam", "suspicious"],
        "low": ["parked-domain", "low-reputation"],
        "info": ["benign-observed"],
    }

    def _demo_findings(self, norm) -> list[dict]:
        """Deterministic, clearly-labelled sample findings (RFC 5737 ranges)."""
        from ..utils.demo_data import DEMO_SOURCE_POOL, demo_geo_for

        seed = int(hashlib.sha256(norm.value.encode()).hexdigest()[:12], 16)
        rng = random.Random(seed)
        bucket = seed % 100

        if bucket < 8:
            severity, score = "critical", rng.randint(85, 98)
        elif bucket < 30:
            severity, score = "high", rng.randint(70, 84)
        elif bucket < 60:
            severity, score = "medium", rng.randint(45, 69)
        elif bucket < 85:
            severity, score = "low", rng.randint(20, 44)
        else:
            severity, score = "info", rng.randint(0, 19)

        geo = demo_geo_for(norm.value)
        now = utcnow()
        findings: list[dict] = []

        base_meta = {
            "country": geo["country"],
            "asn": geo["asn"],
            "asn_name": geo["asn_name"],
        }

        # Simulate 2-4 demo sources reporting
        chosen = rng.sample(DEMO_SOURCE_POOL, k=rng.randint(2, min(4, len(DEMO_SOURCE_POOL))))
        for i, src in enumerate(chosen):
            s = max(0, min(100, score + rng.randint(-8, 8)))
            fsev = severity if i == 0 else self._band_of(s)
            age = rng.choice([0, 1, 2, 5, 9])
            findings.append({
                "source": f"{src} (Demo)",
                "severity": fsev,
                "confidence": round(0.45 + rng.random() * 0.4, 2),
                "score": s if src != "GeoIP" else None,
                "summary": self._demo_summary(norm, fsev, src, rng),
                "tags": rng.sample(self.DEMO_TAGS_BY_SEVERITY[fsev],
                                   k=min(len(self.DEMO_TAGS_BY_SEVERITY[fsev]), rng.randint(1, 3)))
                if fsev != "info" else ["benign-observed"],
                "observed_at": iso(now - timedelta(days=age, hours=rng.randint(0, 23))),
                "data": {"demo": True,
                         "reports": rng.randint(1, 240) if fsev in ("critical", "high") else rng.randint(0, 6),
                         "lat": geo["lat"], "lon": geo["lon"], "city": geo["city"],
                         **base_meta},
                "enrich": base_meta,
            })

        self.events.publish(
            "lookup.demo",
            f"Demonstration intelligence generated for {norm.value} "
            "(labelled sample data — not live threat information)",
            severity="info",
        )
        return findings

    @staticmethod
    def _band_of(s: int) -> str:
        if s >= 85: return "critical"
        if s >= 70: return "high"
        if s >= 45: return "medium"
        if s >= 20: return "low"
        return "info"

    @staticmethod
    def _demo_summary(norm, severity: str, src: str, rng: random.Random) -> str:
        actions = {
            "critical": ["Repeated C2 beacon patterns", "Malware payload distribution", "Command-and-control infrastructure"],
            "high": ["Malicious payload delivery observed", "Active scanning campaigns", "Credential harvesting attempts"],
            "medium": ["Elevated connection attempts", "Spam origination", "Suspicious certificate patterns"],
            "low": ["Minor reputation issues", "Unusual traffic volume", "Recently parked infrastructure"],
            "info": ["No abuse reports on record", "Benign usage patterns"],
        }[severity]
        return f"[SAMPLE DATA] {rng.choice(actions)} — demonstration record from {src}."
