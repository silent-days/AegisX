"""AegisX — application logging (rotating file + console)."""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .paths import logs_dir

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_configured = False


def setup_logging(level: str | None = None) -> Path:
    """Configure the root logger; safe to call multiple times."""
    global _configured
    log_file = logs_dir() / "aegisx.log"

    if level is None:
        level = os.environ.get("AEGISX_LOG_LEVEL", "INFO")
    lvl = getattr(logging, str(level).upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(lvl)
    if _configured:
        return log_file

    fmt = logging.Formatter(_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

    fh = RotatingFileHandler(log_file, maxBytes=1_500_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    if os.environ.get("AEGISX_CONSOLE_LOG", "0") == "1" or not sys.stdout.isatty():
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        root.addHandler(ch)

    # Quiet down noisy third-party loggers.
    for noisy in ("urllib3", "requests", "matplotlib", "PyQtGraph"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True
    logging.getLogger("aegisx").info("Logging initialised -> %s", log_file)
    return log_file


def get_logger(name: str = "aegisx") -> logging.Logger:
    return logging.getLogger(name)


def log_file_path() -> Path:
    return logs_dir() / "aegisx.log"
