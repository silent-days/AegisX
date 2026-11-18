# AegisX — Feature Reference

Every page of the application, what it does, and where its data comes from.

## 1. Dashboard (v1.0 — premium 3D)
- **Command Metrics strip**: four hand-painted 3D-style radial gauges with gradient rings, specular gloss, inset dials and animated count-ups — Threat Index (avg risk), Detection Confidence, High-Risk Exposure, Corpus Coverage.
- **Global threat topology in 3D**: perspective floor grid (holographic projector plane), depth-scaled nodes with ground shadows and specular highlights, pedestal-shadowed hubs with glossy beads.
- 30-day threat activity timeline (PyQtGraph area chart).
- Severity distribution donut (animated sweep).
- Global threat mini-map plotting geo-coded indicators.
- Recent intelligence feed (persisted events, relative timestamps).
- Intelligence source status board (per-provider state chips).
- Infrastructure correlation activity (relationship counter + latest links).
- Demonstration-mode banner whenever demo data is shown.

## 2. Global Threat Map
- Custom dot-matrix world map — fully offline, no tile service.
- Pulsing severity-coloured markers with click-to-select detail panel.
- Animated attack arcs with travelling comet heads.
- Severity/type filters; animated-flow demonstration feed toggle.
- Stats strip: plotted indicators, countries, active flows.

## 3. Threat Intelligence (advanced IOC manager — v1.0)
- Searchable, filterable, paginated table (risk/recent/confidence/value ordering).
- **Per-row quick Remove button** plus a right-click context menu: open details, copy value, re-analyze, add tag, remove.
- **Multi-select bulk operations**: Remove selected, Re-scan selected, Tag selected, Export selected (CSV) — surfaced in a red bulk-action bar.
- **Advanced filter panel** (collapsible): intelligence source, tag match, minimum risk slider, recency window (24 h / 7 d / 30 d) and one-click reset.
- **Remove all filtered** — guarded bulk cleanup of everything matching the current filters, with a typed confirmation showing the exact count.
- Detail dialog: context, relationship list, full finding history, delete (Cancel is now properly respected).
- CSV import (auto-analyzes each row), CSV/JSON export (JSON honours active filters).
- Manual indicator addition — runs the full analysis pipeline.

## 4. IP Investigation
- Validated IP input; async multi-provider lookup with progress spinner.
- Animated risk gauge + verdict + factor-by-factor evidence breakdown.
- Per-source finding cards: score bar, summary, key metrics, tags, timestamps.
- Geolocation mini-map and network context (ASN, country, ISP).
- MITRE ATT&CK association chips.
- Actions: add to investigation, copy JSON, force refresh.
- Explicit banner for key-required providers that were skipped.

## 5. Domain Intelligence
- Real DNS resolution (A/AAAA) and TLS certificate inspection (subject,
  issuer, validity, SAN) with graceful offline handling.
- Provider reputation cards (URLhaus/ThreatFox work key-free).
- Domain→IP resolution feeds `resolves-to` relationships.

## 6. Infrastructure Analysis
- Top hosting countries and indicator type distribution charts.
- Autonomous systems table (count, average risk).
- Infrastructure clusters (union-find over relationships) with interactive
  force-directed graph per cluster/ASN.

## 7. Threat Correlation
- Build a relationship graph around any indicator (1–2 hop expansion).
- Toggleable relationship kinds; physics-simulated graph with drag/zoom/pan.
- Evidence panel per node/edge with confidence and derivation text.
- On-demand analysis when the indicator isn't in the database yet.

## 8. Campaign Intelligence
- Campaign cards: severity, confidence, indicator count, tags, ATT&CK chips.
- Honest attribution handling: provider attribution claims are shown with
  their confidence; otherwise "No attribution claimed" is displayed.
- Detail dialog: timeline fields, member table, ATT&CK associations,
  indicator linking.

## 9. Threat Analytics
- Activity timeline, severity distribution, source contribution, top
  countries, top ASNs, confidence histogram, ATT&CK technique frequency.
- Per-chart PNG export (real widget capture).

## 10. Investigation Workspace
- Investigation list with filter; create/delete with confirmations.
- Editable metadata (name, status, priority, description).
- Indicator items table with add (auto-analyzes), remove.
- Timestamped analyst notes.
- One-click branded report generation (HTML/JSON, async).

## 11. Intelligence Sources
- Provider cards: description, capabilities, key state, rate limits,
  TTL, request/failure counters, last success, last error.
- Real connectivity tests (cheap, provider-specific endpoints).
- Docs links, configure dialog, "test all", cache stats and clear cache.

## 12. Reports
- Report table (title, format, created, size) with open-in-viewer.
- Generation from any investigation; files stored under
  `~/.local/share/aegisx/reports/`.
- HTML reports are self-contained (inline CSS + embedded logo) — print to
  PDF from any browser.

## 13. Settings
- Provider configuration (per-provider dialog with live test).
- Demonstration mode toggle, analyst name.
- Data & cache: clear cache, open folders, full JSON export, wipe database
  (with confirmation; config/keys are kept).
- Logging level and log-folder shortcut.

## 14. About AegisX
- Brand hero, capability summary, technology stack, developer credit
  (Silent Days), Kali Linux badge, MIT license, methodology & disclaimers,
  real runtime environment info.

## Cross-cutting
- **Splash screen** — 2-second branded boot with animated progress.
- **Toasts** — severity-accented, auto-dismissing, slide-in animation.
- **Notification bell** — recent event history dropdown.
- **Global search** — title-bar search routes into the IOC browser.
- **Keyboard** — Enter to run lookups; all buttons perform real actions.
