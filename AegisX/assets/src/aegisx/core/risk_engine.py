"""
AegisX — evidence-based risk scoring engine.

Produces a transparent 0-100 risk score, severity band and confidence from
multi-source findings. Every score carries a factor breakdown so the UI can
show *why* an indicator received its rating (no black boxes, no attribution
claims).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# Relative trust in each source (0..1). Used for confidence weighting.
SOURCE_RELIABILITY = {
    "VirusTotal":  0.92,
    "AbuseIPDB":   0.88,
    "URLhaus":     0.90,
    "ThreatFox":   0.85,
    "AlienVault OTX": 0.80,
    "GeoIP":       0.60,
    "Demo Feed":   0.50,
    "Local Analysis": 0.75,
}

CRITICAL_TAGS = {
    "c2", "c2-server", "ransomware", "botnet", "exploit-kit", "loader",
    "credential-phishing", "command-and-control", "dga", "fast-flux",
}

BANDS = (
    (85, "critical"),
    (70, "high"),
    (45, "medium"),
    (20, "low"),
    (0,  "info"),
)

SCORE_WEIGHTS = {
    "VirusTotal": 0.95,
    "AbuseIPDB": 0.90,
    "URLhaus": 1.00,       # URLhaus listings are manually verified
    "ThreatFox": 0.95,
    "AlienVault OTX": 0.55,
    "Local Analysis": 0.70,
}


@dataclass
class ScoreFactor:
    label: str
    impact: int          # signed contribution (for UI transparency)
    detail: str = ""


@dataclass
class RiskResult:
    score: int = 0
    severity: str = "info"
    confidence: float = 0.0
    factors: list[ScoreFactor] = field(default_factory=list)
    verdict: str = ""

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "factors": [f.__dict__ for f in self.factors],
            "verdict": self.verdict,
        }


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "info"


def _score_of(finding: dict) -> int | None:
    score = finding.get("score")
    if score is None:
        return None
    try:
        return max(0, min(100, int(score)))
    except (TypeError, ValueError):
        return None


def _freshness_penalty(observed_at: str | None) -> float:
    """0.0 (fresh) .. 1.0 (very old) multiplier for staleness."""
    if not observed_at:
        return 0.10
    try:
        dt = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
    except ValueError:
        return 0.10
    age_days = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 86400)
    if age_days <= 7:
        return 0.0
    if age_days >= 180:
        return 0.45
    return (age_days - 7) / 173 * 0.45


def score_indicator(findings: list[dict], *, indicator_meta: dict | None = None) -> RiskResult:
    """
    findings: list of dicts with at least {source, score?, severity, tags?,
    observed_at?}. indicator_meta may carry {type} for context adjustments.
    """
    meta = indicator_meta or {}
    factors: list[ScoreFactor] = []
    scored: list[tuple[str, int, float]] = []   # (source, score, weight)

    for f in findings:
        s = _score_of(f)
        if s is None:
            continue
        weight = SCORE_WEIGHTS.get(f.get("source", ""), 0.5)
        sev = (f.get("severity") or "info").lower()
        if sev == "critical" and s < 85:
            s = max(s, 85)
        scored.append((f.get("source", "unknown"), s, weight))

    if scored:
        total_w = sum(w for _, _, w in scored)
        base = sum(s * w for _, s, w in scored) / max(total_w, 1e-6)
    else:
        base = 0.0

    factors.append(ScoreFactor(
        "Weighted source consensus",
        int(round(base)) - 0,
        f"{len(scored)} scored source(s): " + ", ".join(f"{src}={s}" for src, s, _ in scored[:6])
        if scored else "No scored source reported a numeric score",
    ))

    score = base

    # Source corroboration bonus
    distinct_sources = len({f.get("source") for f in findings if f.get("source")})
    bonus = min(20, max(0, distinct_sources - 1) * 7)
    if bonus:
        factors.append(ScoreFactor("Multi-source corroboration", +bonus,
                                   f"Corroborated by {distinct_sources} independent sources"))
    score += bonus

    # Critical tag escalation
    tags = set()
    for f in findings:
        tags |= set(f.get("tags") or [])
    critical_hits = sorted(CRITICAL_TAGS & tags)
    if critical_hits:
        penalty = min(15, 5 * len(critical_hits))
        factors.append(ScoreFactor("High-impact behaviour tags", +penalty,
                                   ", ".join(critical_hits[:5])))
        score += penalty

    # Staleness
    observed = [f.get("observed_at") for f in findings if f.get("observed_at")]
    newest = max(observed) if observed else None
    staleness = _freshness_penalty(newest)
    if staleness > 0:
        adj = -int(round(score * staleness))
        factors.append(ScoreFactor("Report freshness decay", adj,
                                   "Findings are aged; risk may have changed"))
        score += adj

    # URL/hash types start slightly elevated when any source flagged them
    if meta.get("type") in ("url", "hash") and scored and score < 10:
        score = min(score + 5, 100)

    score = int(max(0, min(100, round(score))))

    # Confidence: source reliability + breadth
    rels = [SOURCE_RELIABILITY.get(f.get("source", ""), 0.5) for f in findings]
    conf = (sum(rels) / max(len(rels), 1)) if rels else 0.0
    conf = min(1.0, 0.35 + 0.65 * conf + 0.05 * max(0, distinct_sources - 1))

    severity = band_for(score)
    verdict = {
        "critical": "Critical threat — immediate containment recommended",
        "high":     "High risk — restrict and investigate",
        "medium":   "Suspicious — monitor and verify",
        "low":      "Low risk — limited evidence of abuse",
        "info":     "No significant abuse reported by available sources",
    }[severity]

    return RiskResult(score=score, severity=severity, confidence=conf,
                      factors=factors, verdict=verdict)
