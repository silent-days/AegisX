"""
AegisX — filesystem path resolution.

Follows the XDG Base Directory specification and the Kali Linux
permanent-installation layout:

    Application : /opt/AegisX/
    Config      : ~/.config/aegisx/
    User data   : ~/.local/share/aegisx/
    Logs        : ~/.local/state/aegisx/
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR_NAME = "AegisX"

# ---------------------------------------------------------------------------
# XDG helpers
# ---------------------------------------------------------------------------

def _xdg(env_var: str, fallback: Path) -> Path:
    raw = os.environ.get(env_var, "").strip()
    if raw:
        first = Path(raw.split(":")[0]).expanduser()
        return first
    return fallback


def home() -> Path:
    return Path.home()


def config_dir() -> Path:
    """~/.config/aegisx — settings, key store fallback, env file.

    Resolution: AEGISX_CONFIG_HOME override > XDG_CONFIG_HOME > ~/.config.
    """
    override = os.environ.get("AEGISX_CONFIG_HOME", "").strip()
    if override:
        d = Path(override).expanduser() / "aegisx"
    else:
        d = _xdg("XDG_CONFIG_HOME", home() / ".config") / "aegisx"
    _ensure(d)
    return d


def data_dir() -> Path:
    """~/.local/share/aegisx — database, reports, exports.

    Resolution: AEGISX_DATA_HOME override > XDG_DATA_HOME > ~/.local/share.
    """
    override = os.environ.get("AEGISX_DATA_HOME", "").strip()
    if override:
        d = Path(override).expanduser() / "aegisx"
    else:
        d = _xdg("XDG_DATA_HOME", home() / ".local" / "share") / "aegisx"
    _ensure(d / "reports")
    _ensure(d / "exports")
    return d


def state_dir() -> Path:
    """~/.local/state/aegisx — runtime state.

    Resolution: AEGISX_STATE_HOME override > XDG_STATE_HOME > ~/.local/state.
    """
    override = os.environ.get("AEGISX_STATE_HOME", "").strip()
    if override:
        d = Path(override).expanduser() / "aegisx"
    else:
        d = _xdg("XDG_STATE_HOME", home() / ".local" / "state") / "aegisx"
    _ensure(d)
    return d


def logs_dir() -> Path:
    """~/.local/state/aegisx/logs"""
    d = state_dir() / "logs"
    _ensure(d)
    return d


def _ensure(d: Path) -> Path:
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


# ---------------------------------------------------------------------------
# Application installation root / assets
# ---------------------------------------------------------------------------

def app_root() -> Path:
    """
    Root directory of the application installation.

    Resolution order:
      1. ``AEGISX_ROOT`` environment override
      2. ``/opt/AegisX`` when it exists (permanent Kali installation)
      3. Repository root when running from source (two levels above src/)
    """
    override = os.environ.get("AEGISX_ROOT", "").strip()
    if override and Path(override).is_dir():
        return Path(override)

    opt = Path("/opt") / APP_DIR_NAME
    if opt.is_dir() and (opt / "assets").is_dir():
        return opt

    # Running from source: <repo>/src/aegisx/utils/paths.py
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "assets").is_dir() and (parent / "src").is_dir():
            return parent
    # Fallback: package parent (installed as python package)
    pkg_root = here.parents[2]
    return pkg_root


def assets_dir(*sub: str) -> Path:
    d = app_root() / "assets"
    for part in sub:
        d = d / part
    return d


def asset(*parts: str) -> Path:
    """Return an asset path if it exists, otherwise a best-guess path."""
    p = assets_dir(*parts)
    return p if p.exists() else assets_dir(*parts[:1])


def database_path() -> Path:
    override = os.environ.get("AEGISX_DB", "").strip()
    if override:
        p = Path(override).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    return data_dir() / "aegisx.db"


def reports_dir() -> Path:
    d = data_dir() / "reports"
    _ensure(d)
    return d


def exports_dir() -> Path:
    d = data_dir() / "exports"
    _ensure(d)
    return d


# ---------------------------------------------------------------------------
# Optional environment file  (~/.config/aegisx/aegisx.env)
# ---------------------------------------------------------------------------

def load_env_file() -> int:
    """
    Load KEY=VALUE pairs from ~/.config/aegisx/aegisx.env into os.environ
    (without overriding variables that are already set). Returns the number
    of variables applied.
    """
    env_file = config_dir() / "aegisx.env"
    applied = 0
    try:
        if not env_file.is_file():
            return 0
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
                applied += 1
    except OSError:
        pass
    return applied


def is_installed_permanently() -> bool:
    """True when running from the permanent /opt/AegisX installation."""
    return app_root() == Path("/opt") / APP_DIR_NAME


def python_version_string() -> str:
    return sys.version.split()[0]
