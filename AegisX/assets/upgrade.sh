#!/usr/bin/env bash
# ============================================================================
#  AegisX — Upgrader
#
#  Usage:  sudo bash upgrade.sh [--backup]
#
#  Upgrades an existing /opt/AegisX installation in place. The installer is
#  idempotent, so upgrading is a safe re-run with an optional backup of user
#  data beforehand. Configuration, investigations and reports are preserved.
# ============================================================================
set -euo pipefail

APP_KEY="aegisx"
BACKUP=0
[[ "${1:-}" == "--backup" ]] && BACKUP=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
echo ""
echo -e "${BOLD}=============================================================="
echo -e "   AegisX — Upgrade"
echo -e "==============================================================${NC}"
echo ""

if [[ ! -d /opt/AegisX ]]; then
  echo -e "No existing installation found at /opt/AegisX."
  echo -e "Performing a fresh installation instead…"
  exec bash "$SCRIPT_DIR/install.sh"
fi

if [[ $BACKUP -eq 1 ]]; then
  STAMP="$(date +%Y%m%d-%H%M%S)"
  TARGET="${HOME}/aegisx-backup-${STAMP}.tar.gz"
  echo -e "${BLUE}[*]${NC} Backing up user data to ${TARGET}…"
  tar -czf "$TARGET" \
      -C "$HOME" \
      ".config/${APP_KEY}" ".local/share/${APP_KEY}" ".local/state/${APP_KEY}" \
      2>/dev/null || true
  echo -e "${GREEN}[✓]${NC} Backup saved: ${TARGET}"
fi

echo -e "${BLUE}[*]${NC} Running idempotent installer (user data is preserved)…"
exec bash "$SCRIPT_DIR/install.sh"
