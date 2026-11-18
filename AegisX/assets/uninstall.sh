#!/usr/bin/env bash
# ============================================================================
#  AegisX — Uninstaller for Kali Linux / Debian
#
#  Usage:
#    sudo bash uninstall.sh              # remove app, KEEP user data (default)
#    sudo bash uninstall.sh --purge-data # also remove config/data/logs (ask)
#    sudo bash uninstall.sh --purge-data --yes  # no confirmation prompt
# ============================================================================
set -euo pipefail

APP_NAME="AegisX"
APP_KEY="${APP_NAME,,}"
INSTALL_DIR="/opt/${APP_NAME}"
LAUNCHER="/usr/local/bin/${APP_KEY}"
DESKTOP_ENTRY="/usr/share/applications/${APP_KEY}.desktop"
ICON_SYS="/usr/share/icons/hicolor/256x256/apps/${APP_KEY}.png"

USER_DIRS=(
  "${HOME}/.config/${APP_KEY}"
  "${HOME}/.local/share/${APP_KEY}"
  "${HOME}/.local/state/${APP_KEY}"
)

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${BLUE}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

PURGE_DATA=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --purge-data) PURGE_DATA=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    *)            warn "Unknown option: $arg" ;;
  esac
done

echo ""
echo -e "${BOLD}=============================================================="
echo -e "   AegisX — Uninstaller"
echo -e "==============================================================${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
  warn "Run as root to remove system-wide files:  sudo bash uninstall.sh"
  echo ""
  read -r -p "Continue anyway (only user-local pieces will be handled)? [y/N] " ans
  [[ "${ans,,}" == "y" ]] || exit 1
fi

# application directory -------------------------------------------------------
if [[ -d "$INSTALL_DIR" && -w "$(dirname "$INSTALL_DIR")" ]]; then
  info "Removing ${INSTALL_DIR}…"
  rm -rf "$INSTALL_DIR"
  ok "Application directory removed"
else
  info "No application directory found at ${INSTALL_DIR} (already removed?)"
fi

# launcher --------------------------------------------------------------------
if [[ -e "$LAUNCHER" ]] && { [[ -w "/usr/local/bin" ]] || [[ $EUID -eq 0 ]]; }; then
  info "Removing launcher ${LAUNCHER}…"
  rm -f "$LAUNCHER"
  ok "Launcher removed"
else
  info "Launcher ${LAUNCHER} not present (already removed?)"
fi

# desktop entry -----------------------------------------------------------------
if [[ -e "$DESKTOP_ENTRY" ]] && { [[ -w "/usr/share/applications" ]] || [[ $EUID -eq 0 ]]; }; then
  rm -f "$DESKTOP_ENTRY"
  ok "Desktop entry removed"
fi

# icon ------------------------------------------------------------------------------
if [[ -e "$ICON_SYS" ]] && { [[ -w "/usr/share/icons/hicolor/256x256/apps" ]] || [[ $EUID -eq 0 ]]; }; then
  rm -f "$ICON_SYS"
  command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
  ok "System icon removed"
fi

# user data ---------------------------------------------------------------------------
if [[ $PURGE_DATA -eq 1 ]]; then
  echo ""
  warn "Purge requested — the following user data will be DELETED:"
  for d in "${USER_DIRS[@]}"; do
    [[ -d "$d" ]] && echo -e "    - ${BOLD}${d}${NC} ($(du -sh "$d" 2>/dev/null | cut -f1))"
  done
  echo ""
  if [[ $ASSUME_YES -ne 1 ]]; then
    read -r -p "Type 'PURGE' to confirm irreversible deletion of investigations/reports: " ans
    if [[ "$ans" != "PURGE" ]]; then
      info "Purge cancelled — user data preserved."
      PURGE_DATA=0
    fi
  fi
  if [[ $PURGE_DATA -eq 1 ]]; then
    for d in "${USER_DIRS[@]}"; do
      [[ -d "$d" ]] && rm -rf "$d" && ok "Removed ${d}"
    done
  fi
else
  echo ""
  ok "User data preserved by default:"
  for d in "${USER_DIRS[@]}"; do
    [[ -d "$d" ]] && echo -e "    - ${d}"
  done
  echo ""
  info "To also delete investigations, reports and configuration, run:"
  echo -e "    ${BOLD}sudo bash uninstall.sh --purge-data${NC}"
fi

echo ""
echo -e "${GREEN}AegisX uninstalled.${NC} Kali menu entry will disappear on next refresh."
echo ""
