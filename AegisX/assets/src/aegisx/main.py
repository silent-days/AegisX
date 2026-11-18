#!/usr/bin/env python3
"""
AegisX — CLI entry point.

    aegisx                 launch the desktop application
    aegisx --version       print version and exit
    aegisx --reset-db      wipe the local database before launch
    aegisx --console-log   also log to the terminal
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the src/ package importable no matter how we are invoked
# (installed launcher, run.sh, python -m).
_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if "--version" in argv or "-V" in argv:
        from aegisx.version import APP_NAME, APP_VERSION

        print(f"{APP_NAME} {APP_VERSION} — Global Cyber Threat Intelligence")
        print("by Silent Days · MIT License · Designed for Kali Linux")
        return 0

    # heavy imports happen here so --version stays instant
    from aegisx.utils.logger import setup_logging
    from aegisx.utils.paths import config_dir, data_dir, load_env_file

    load_env_file()
    setup_logging()

    if "--reset-db" in argv:
        from aegisx.utils.logger import get_logger
        from aegisx.utils.paths import database_path

        db = database_path()
        removed = []
        for p in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
            if p.is_file():
                p.unlink()
                removed.append(p.name)
        get_logger("aegisx").info("Database reset: %s", removed or "nothing to remove")

    if "--info" in argv:
        from aegisx.version import APP_VERSION
        from aegisx.utils.paths import app_root, database_path, is_installed_permanently

        print(f"AegisX {APP_VERSION}")
        print(f"  install root : {app_root()} ({'permanent' if is_installed_permanently() else 'source'})")
        print(f"  database     : {database_path()}")
        print(f"  config dir   : {config_dir()}")
        return 0

    from aegisx.application import run

    return run(argv)


if __name__ == "__main__":
    raise SystemExit(main())
