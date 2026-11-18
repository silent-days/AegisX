#!/usr/bin/env bash
# ============================================================================
#  AegisX — Global Cyber Threat Intelligence
#  Permanent installer for Kali Linux / Debian systems.
#
#  Usage:  sudo bash install.sh
#
#  Installs to /opt/AegisX with an isolated virtual environment, a system
#  launcher (/usr/local/bin/aegisx), a desktop entry and the brand icon.
#  Idempotent: safe to re-run for upgrades. User data (~/.config/aegisx,
#  ~/.local/share/aegisx, ~/.local/state/aegisx) is NEVER touched.
# ============================================================================
set -euo pipefail

# ------------------------------------------------------------------ config --
APP_NAME="AegisX"
INSTALL_DIR="/opt/${APP_NAME}"
LAUNCHER="/usr/local/bin/${APP_NAME,,}"
DESKTOP_ENTRY="/usr/share/applications/${APP_NAME,,}.desktop"
ICON_SRC="assets/icons/aegisx.png"
ICON_SYS="/usr/share/icons/hicolor/256x256/apps/${APP_NAME,,}.png"
MIN_PYTHON="3.9"
VENV_DIR="${INSTALL_DIR}/venv"

# system libraries required by Qt6/PySide6 on Kali/Debian
SYSTEM_PACKAGES=(
  python3 python3-venv python3-pip
  libgl1 libegl1 libxkbcommon0 libdbus-1-3 libfontconfig1 libglib2.0-0
  libx11-6 libx11-xcb1 libxcb1 libxcb-cursor0 libxcb-icccm4 libxcb-image0
  libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0
  libxcb-xinerama0 libxcb-xfixes0
  xdg-utils ca-certificates
)

# ------------------------------------------------------------------ output --
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# ------------------------------------------------------------------- setup --
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo -e "${BOLD}=============================================================="
echo -e "   AegisX — Global Cyber Threat Intelligence Installer"
echo -e "   by Silent Days · for Kali Linux"
echo -e "==============================================================${NC}"
echo ""

# 1. root check
if [[ $EUID -ne 0 ]]; then
  fail "This installer must run as root. Use:  sudo bash install.sh"
fi
ok "Running with root privileges"

# 2. OS compatibility ---------------------------------------------------------
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-}" in
    kali)   ok "Detected Kali Linux ${VERSION_ID:-}" ;;
    debian) ok "Detected Debian ${VERSION_ID:-} (compatible)" ;;
    *)      warn "Detected '${PRETTY_NAME:-unknown}' — AegisX targets Kali Linux."
            read -r -p "    Continue anyway? [y/N] " ans
            [[ "${ans,,}" == "y" ]] || fail "Installation aborted." ;;
  esac
else
  warn "/etc/os-release not found — continuing on unknown distribution."
fi

# 3. Python version -----------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found. Install Python ${MIN_PYTHON}+ first."
fi
PY_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_OK="$(python3 -c "import sys; print(1 if sys.version_info >= (${MIN_PYTHON%.*}, ${MIN_PYTHON#*.}) else 0)")"
if [[ "$PY_OK" != "1" ]]; then
  fail "Python ${PY_VERSION} found — AegisX requires Python ${MIN_PYTHON}+."
fi
ok "Python ${PY_VERSION} detected"

# 4. existing installation -----------------------------------------------------
UPGRADE=0
if [[ -d "$INSTALL_DIR" && -x "$LAUNCHER" ]]; then
  UPGRADE=1
  warn "Existing installation detected — upgrading in place."
  info "Your configuration, investigations and intelligence data are preserved."
fi

# 5. system dependencies --------------------------------------------------------
info "Installing system dependencies (apt)…"
export DEBIAN_FRONTEND=noninteractive
if ! apt-get update -qq >>/var/log/aegisx-install.log 2>&1; then
  warn "apt-get update reported warnings (continuing — see /var/log/aegisx-install.log)"
fi
apt-get install -y -qq "${SYSTEM_PACKAGES[@]}" >>/var/log/aegisx-install.log 2>&1 \
  || fail "System package installation failed — check /var/log/aegisx-install.log"
ok "System dependencies installed"

# 6. create /opt/AegisX ---------------------------------------------------------
info "Creating ${INSTALL_DIR}…"
mkdir -p "$INSTALL_DIR"
ok "Application directory ready"

# 7. copy application files ------------------------------------------------------
info "Copying application files…"
# Remove previous app payload only (venv + user data elsewhere are preserved)
rm -rf "${INSTALL_DIR}/src" "${INSTALL_DIR}/assets" "${INSTALL_DIR}/docs" \
       "${INSTALL_DIR}/tests" "${INSTALL_DIR}/scripts"
cp -a src "$INSTALL_DIR/"
cp -a assets "$INSTALL_DIR/"
cp -a docs "$INSTALL_DIR/"
cp -a tests "$INSTALL_DIR/"
for f in entrypoint.py requirements.txt README.md LICENSE config.example.env \
         install.sh uninstall.sh upgrade.sh run.sh; do
  [[ -f "$f" ]] && cp -a "$f" "$INSTALL_DIR/" || true
done
ok "Application files copied"

# 8. isolated virtual environment -------------------------------------------------
info "Creating isolated Python virtual environment…"
rm -rf "$VENV_DIR"   # recreate on each install for dependency consistency
python3 -m venv "$VENV_DIR" || fail "Failed to create virtual environment (is python3-venv installed?)"
ok "Virtual environment created at ${VENV_DIR}"

# 9. python dependencies inside the venv --------------------------------------------
info "Installing Python dependencies inside the virtual environment…"
if ! "${VENV_DIR}/bin/pip" install --quiet --upgrade pip >>/var/log/aegisx-install.log 2>&1; then
  warn "pip upgrade failed (continuing with bundled pip)"
fi
if ! "${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt" >>/var/log/aegisx-install.log 2>&1; then
  fail "Python dependency installation failed. Check network connectivity and /var/log/aegisx-install.log"
fi
ok "Python dependencies installed (PySide6, PyQtGraph, requests)"

# 10. system-wide launcher ----------------------------------------------------------
info "Creating launcher at ${LAUNCHER}…"
cat > "$LAUNCHER" <<EOF
#!/bin/bash
# AegisX launcher — generated by install.sh
export QT_QPA_PLATFORMTHEME=""
export AEGISX_ROOT="${INSTALL_DIR}"
exec "${VENV_DIR}/bin/python" "${INSTALL_DIR}/entrypoint.py" "\$@"
EOF
chmod 755 "$LAUNCHER"
ok "Launcher installed — run the app with:  ${APP_NAME,,}"

# 11. desktop entry -------------------------------------------------------------------
info "Creating desktop entry at ${DESKTOP_ENTRY}…"
cat > "$DESKTOP_ENTRY" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=AegisX
GenericName=Cyber Threat Intelligence
Comment=Global Cyber Threat Intelligence — collect, analyze, correlate and visualize threats
Exec=${APP_NAME,,}
TryExec=${APP_NAME,,}
Path=${INSTALL_DIR}
Icon=${ICON_SYS}
Terminal=false
Categories=Security;Network;Utility;
Keywords=threat;intelligence;osint;security;ioc;cyber;kali;
StartupWMClass=AegisX
StartupNotify=true
EOF
chmod 644 "$DESKTOP_ENTRY"
ok "Desktop entry installed — AegisX is in the Kali applications menu"

# 12. application icon -------------------------------------------------------------------
info "Installing application icon…"
if [[ -f "$ICON_SRC" ]]; then
  mkdir -p "$(dirname "$ICON_SYS")"
  cp -a "$ICON_SRC" "$ICON_SYS"
  chmod 644 "$ICON_SYS"
  command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true
  ok "Icon installed at ${ICON_SYS}"
else
  warn "Icon asset missing — desktop entry will use a fallback icon."
fi

# 13. permissions ----------------------------------------------------------------------------
info "Configuring permissions…"
chown -R root:root "$INSTALL_DIR"
find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$LAUNCHER" "$INSTALL_DIR/entrypoint.py"
ok "Permissions set (safe 755/644 — no world-writable paths)"

# 14. validate ----------------------------------------------------------------------------------
info "Validating installation…"
if QT_QPA_PLATFORM=offscreen "$LAUNCHER" --version >/dev/null 2>&1; then
  VERSION_OUT="$(QT_QPA_PLATFORM=offscreen "$LAUNCHER" --version | head -1)"
  ok "Validation passed: ${VERSION_OUT}"
else
  fail "Validation failed — run '${LAUNCHER} --version' to see the error."
fi

# 15. summary ------------------------------------------------------------------------------------
USER_DATA_DIRS=(
  "${HOME}/.config/${APP_NAME,,}"
  "${HOME}/.local/share/${APP_NAME,,}"
  "${HOME}/.local/state/${APP_NAME,,}"
)
echo ""
echo -e "${BOLD}=============================================================="
echo -e "${GREEN}   AegisX installed successfully!${NC}"
echo -e "${BOLD}==============================================================${NC}"
echo ""
echo -e "  Application   : ${BLUE}${INSTALL_DIR}${NC}"
echo -e "  Launcher      : ${BLUE}${LAUNCHER}${NC}"
echo -e "  Desktop entry : ${BLUE}${DESKTOP_ENTRY}${NC}"
echo -e "  Icon          : ${BLUE}${ICON_SYS}${NC}"
echo -e "  Config / Data : ${BLUE}${USER_DATA_DIRS[0]}${NC}, ${BLUE}${USER_DATA_DIRS[1]}${NC}"
echo -e "  Logs          : ${BLUE}${USER_DATA_DIRS[2]}${NC}"
echo -e "  Virtual env   : ${BLUE}${VENV_DIR}${NC}"
if [[ $UPGRADE -eq 1 ]]; then
  echo -e "  Upgrade       : ${GREEN}existing installation updated${NC}"
fi
echo ""
echo -e "  ${BOLD}Launch now:${NC}"
echo -e "    ${GREEN}${APP_NAME,,}${NC}                  (terminal)"
echo -e "    Kali Applications Menu → Security → AegisX"
echo ""
echo -e "  First steps inside the app:"
echo -e "    1. Settings → Intelligence Sources → add your API keys"
echo -e "       (3 keyless community sources work immediately — no key, no setup)"
echo -e "    2. Until keys are configured, AegisX runs in clearly-labelled"
echo -e "       Demonstration Mode with sample data (RFC 5737 test ranges)."
echo ""
echo -e "  Uninstall anytime with:  ${BLUE}sudo bash uninstall.sh${NC}"
echo ""
