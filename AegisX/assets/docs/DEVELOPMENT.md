# AegisX — Development Guide

## Repository layout

```
AegisX/
├── src/aegisx/            # application package
│   ├── ui/                # PySide6 presentation layer
│   ├── core/              # GUI-free intelligence engines
│   ├── providers/         # provider adapters
│   ├── database/          # schema, migrations, repository
│   ├── visualization/     # map, graph, chart widgets
│   ├── reports/           # report generator
│   ├── security/          # credential storage
│   ├── workers/           # QThreadPool task framework
│   ├── utils/             # paths, logging, validators, demo data, exports
│   └── styles/            # theme tokens + QSS
├── tests/                 # pytest suites
├── docs/                  # documentation
└── install.sh …           # packaging
```

## Environment setup

```bash
git clone <your-fork> AegisX && cd AegisX
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
```

Or simply: `bash run.sh` (creates `.venv` automatically).

## Running

```bash
bash run.sh                      # launch from source
python -m aegisx.main --info     # CLI info
QT_QPA_PLATFORM=offscreen python -m aegisx.main   # headless smoke run
```

## Testing

```bash
python -m pytest tests/ -v            # full suite (headless-safe)
QT_QPA_PLATFORM=offscreen python -m pytest tests/ -v
```

Suites:

| File | Covers |
| --- | --- |
| `tests/test_core.py` | normalization, risk scoring, correlation, lifecycle, MITRE mapping |
| `tests/test_providers.py` | provider parsing (offline fixtures), rate limiter, cache, config state |
| `tests/test_database.py` | repository CRUD, relationships, campaigns, cache TTL, settings |
| `tests/test_validation.py` | validators, demo-data integrity (RFC 5737), keystore round-trip |

## Architecture rules

1. **No Qt in core.** `core/`, `providers/`, `database/`, `security/`,
   `utils/` must import cleanly without PySide6 — CI runs pytest with
   `QT_QPA_PLATFORM=offscreen` anyway.
2. **One source of truth for theming.** Colors live in
   `src/aegisx/styles/theme.py`; QSS files use `@token` placeholders that
   `styles/__init__.py` substitutes. Never hard-code colors in pages.
3. **Every finding has provenance.** source, timestamp, confidence — the
   risk engine refuses anonymous scores.
4. **No fabricated data outside demo_data.py.** Demo output is always
   labelled and uses only documentation ranges.
5. **Long operations run on the TaskManager** (`workers/task_manager.py`);
   pages receive results via queued signals, never blocking the UI thread.

## Adding a provider

1. Create `src/aegisx/providers/<name>.py` implementing
   `ProviderAdapter.fetch()` returning normalized findings
   (`providers/base.py::finding`).
2. Declare `name`, `display_name`, `requires_key`, `description`,
   `capabilities`, `docs_url`, `default_ttl`, `min_interval` and the
   `test_connection` attributes.
3. Register it in `providers/__init__.py::PROVIDER_CLASSES`.
4. Add parsing fixtures to `tests/test_providers.py`.
5. (Optional) add a demo source name in `utils/demo_data.py`.

## Adding a page

1. Create `src/aegisx/ui/pages/<name>.py` subclassing `PageBase`
   (`build()` for widgets, `refresh()` for data).
2. Register it in `ui/pages/__init__.py::PAGE_SPECS`.
3. Add a nav entry in `ui/sidebar.py::NAV_SECTIONS`.

## Coding style

- Type hints on public functions; docstrings on modules and classes.
- Exception handling at boundaries (providers, workers) with typed errors.
- Logging via `utils.logger.get_logger`, never bare `print` in app code.
- Lints: keep imports ordered (stdlib → third-party → relative).

## Release checklist

- [ ] `python -m pytest tests/` green
- [ ] `QT_QPA_PLATFORM=offscreen python entrypoint.py --version` OK
- [ ] `sudo bash install.sh` completes on a fresh Kali VM and `aegisx` launches
- [ ] `sudo bash upgrade.sh` preserves data
- [ ] `sudo bash uninstall.sh` removes all system files
- [ ] Splash → main window transition smooth; all 14 pages open
- [ ] Demo mode banners present; no unlabelled synthetic data
- [ ] README screenshots regenerated (see `docs/DEVELOPMENT.md` tip below)

Tip: screenshots can be captured headlessly with `QT_QPA_PLATFORM=offscreen`
using `QWidget.grab()` after navigating pages programmatically.
