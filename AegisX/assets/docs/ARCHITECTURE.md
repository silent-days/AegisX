# AegisX — Architecture

## Layered design

```
┌──────────────────────────────────────────────────────────────────┐
│  Presentation (PySide6)                                          │
│  main_window · titlebar · sidebar · splash · notifications        │
│  pages/* (14 pages) · dialogs/* · components/* · visualization/*  │
├──────────────────────────────────────────────────────────────────┤
│  Application services (services.py ServiceHub)                    │
│  settings · event bus (pub/sub) · worker pool (QThreadPool)       │
├──────────────────────────────────────────────────────────────────┤
│  Core intelligence (pure Python, GUI-free, unit-tested)           │
│  intelligence_engine · correlation_engine · risk_engine           │
│  indicator_manager · mitre mapping                                │
├──────────────────────────────────────────────────────────────────┤
│  Providers (adapters)          │  Persistence (SQLite)            │
│  abuseipdb · otx · virustotal  │  models (migrations)             │
│  urlhaus · threatfox · geoip   │  repository (thread-safe)        │
├────────────────────────────────┴──────────────────────────────────┤
│  Foundation: paths (XDG) · logging · validators · keystore        │
└──────────────────────────────────────────────────────────────────┘
```

**Key rule:** `core/`, `providers/`, `database/`, `security/` and `utils/`
never import Qt. The UI depends on the core — never the reverse. This keeps
every scoring rule and relationship derivation testable headlessly.

## Data flow (indicator lookup)

```
raw input ──▶ normalize (validators)
        ──▶ IndicatorManager.ensure_indicator      (persistence)
        ──▶ Provider fan-out (ThreadPoolExecutor)
              │  per provider: config check → token bucket
              │  → cache (SQLite TTL) → HTTP (timeout/retry)
              │  → parse → normalized Finding dicts
        ──▶ RiskEngine.score_indicator             (weighted consensus)
        ──▶ persistence + scoring + correlation derivation
        ──▶ EventManager.publish → UI toasts / dashboard feed
```

## Risk scoring model (risk_engine.py)

1. **Weighted source consensus** — each provider's score is weighted by
   trust (URLhaus 1.00, VirusTotal 0.95, ThreatFox 0.95, AbuseIPDB 0.90,
   OTX 0.55).
2. **Corroboration bonus** — +7 per additional independent source (cap +20).
3. **Critical-tag escalation** — behaviour tags (c2, ransomware, dga, …)
   add up to +15.
4. **Freshness decay** — up to −45 % for stale evidence (7–180 days).
5. **Bands** — ≥85 critical · ≥70 high · ≥45 medium · ≥20 low · else info.
6. **Confidence** — mean source reliability + breadth (multi-source bonus).

Every score returns a `RiskResult` with a `factors` list; the UI renders
each factor with its signed impact — no black boxes.

## Correlation model (correlation_engine.py)

Relationship kinds, each with evidence text + confidence:

| Kind | Derivation | Confidence |
| --- | --- | --- |
| `same-asn` | indicators share an autonomous system | 0.75 |
| `resolves-to` | DNS finding maps domain → IP indicator | 0.95 |
| `campaign` | co-membership in a campaign | 0.80 |
| `shared-tags` | Jaccard ≥ 0.65 on behaviour tags (same type) | 0.6 × sim |
| `co-investigation` | added to the same investigation | 0.7 |

Clustering uses union-find over stored relationships; clusters expose size,
average risk and dominant tags.

## Caching & rate limiting

- SQLite `cache` table keyed `provider:type:value` with per-provider TTL
  (URLhaus/ThreatFox 2 h, AbuseIPDB/OTX/VT 6 h, GeoIP 30 d).
- `TokenBucket` enforces per-provider minimum request intervals
  (VirusTotal 2.5 s for the public key's 4 req/min, others 1.2–2 s).
- Provider failures map to typed exceptions: `ProviderNotConfigured`,
  `ProviderRateLimited`, `ProviderHTTPError`, `ProviderError`.

## Demonstration mode

`demo_data.py` generates deterministic, labelled sample intelligence seeded
by `sha256(value)` — the same indicator always yields the same demo result.
Only RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
and reserved TLDs (`.example`, `.test`) are used. Every demo finding carries
`"(Demo)"` source names and `[SAMPLE DATA]` summaries; pages show an amber
banner and the map shows a watermark.

## Event bus

`core/event_manager.py` is a thread-safe pub/sub with a 200-event ring
buffer. Workers publish from any thread; the main window bridges to the UI
thread via `QTimer.singleShot(0, …)` and surfaces notable events as toasts
and dashboard feed entries (persisted in the `events` table).

## Database schema (v1)

`indicators`, `findings`, `relationships` (UNIQUE per source/target/kind),
`campaigns`, `campaign_indicators`, `investigations`, `investigation_items`,
`reports`, `events`, `source_status`, `cache`, `settings`.
SQLite WAL mode, foreign keys ON, versioned via `PRAGMA user_version`.

## Frameless window shell

`MainWindow` uses `Qt.FramelessWindowHint` with a custom title bar (drag,
double-click maximize, window buttons), `QWindowHandle.startSystemResize`
edge grips, `QGraphicsOpacityEffect` page transitions and a `ToastHost`
overlay — all standard Qt APIs, X11- and Wayland-safe.

## Startup sequence

```
main.py → load env → logging → QApplication (theme + fonts)
        → init_services (repo, keystore, engines)
        → SplashScreen (2 s branded animation)
        → MainWindow (lazy page construction on first visit)
```
