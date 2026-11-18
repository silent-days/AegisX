#!/usr/bin/env python3
"""
AegisX — installed entrypoint.

Used by the system-wide launcher at /usr/local/bin/aegisx after a permanent
installation to /opt/AegisX. Ensures the source tree is importable and
forwards to the application CLI.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aegisx.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
