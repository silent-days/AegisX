#!/usr/bin/env bash
# ============================================================================
#  AegisX — development runner (run from the source tree, no install needed)
#
#  Usage:  bash run.sh [--demo] [any other aegisx args]
#
#  Creates a local virtual environment (.venv) on first run, installs
#  requirements into it, and launches the application from source.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV=".venv"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "[*] Creating local virtual environment (.venv)…"
  python3 -m venv "$VENV"
fi

echo "[*] Ensuring Python dependencies…"
"$VENV/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install --quiet -r requirements.txt

echo "[*] Launching AegisX…"
export AEGISX_ROOT="$SCRIPT_DIR"
exec "$VENV/bin/python" entrypoint.py "$@"
