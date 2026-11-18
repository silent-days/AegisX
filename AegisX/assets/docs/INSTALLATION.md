# AegisX — Installation Guide (Kali Linux)

This guide covers the permanent one-command installation, launching, upgrading
and complete removal of AegisX on Kali Linux and compatible Debian systems.

## Requirements

| Requirement | Value |
| --- | --- |
| OS | Kali Linux (Debian-compatible; others prompt before continuing) |
| Privileges | `sudo` / root for installation |
| Python | 3.9 or newer (checked automatically) |
| Network | Required once, for `apt` and `pip` during installation |
| Disk | ~600 MB after dependencies |

## One-command installation

```bash
sudo bash install.sh
```

### What the installer does (in order)

1. **Root check** — refuses to run without `sudo`/root.
2. **OS detection** — validates `/etc/os-release` for Kali/Debian.
3. **Python check** — requires ≥ 3.9.
4. **System dependencies** — installs Qt runtime libraries via `apt`
   (`libgl1`, `libegl1`, `libxkbcommon0`, `libxcb-cursor0`, …).
5. **`/opt/AegisX/`** — creates the application directory.
6. **File copy** — copies `src/`, `assets/`, `docs/`, `tests/` and scripts.
7. **Virtual environment** — creates `/opt/AegisX/venv` (isolated).
8. **Python packages** — installs PySide6, PyQtGraph and requests **inside
   the venv** — never into Kali's system Python.
9. **Launcher** — writes `/usr/local/bin/aegisx` (no PATH editing needed).
10. **Desktop entry** — writes `/usr/share/applications/aegisx.desktop`
    (Category: Security) so AegisX appears in the Kali Applications Menu.
11. **Icon** — installs `/usr/share/icons/hicolor/256x256/apps/aegisx.png`.
12. **Permissions** — root-owned `755` directories / `644` files. The
    installer never uses unsafe settings such as `chmod 777`.
13. **Validation** — runs `aegisx --version` headlessly and prints a summary.

Installation failures leave a log at `/var/log/aegisx-install.log`.

## Launch

```bash
aegisx
```

or via the menu: **Kali Applications → Security → AegisX**.

Useful CLI flags:

```bash
aegisx --version      # print version
aegisx --info         # installation paths and database location
aegisx --demo         # force demonstration mode for this session
aegisx --reset-db     # wipe the local database before launch
aegisx --console-log  # also log to the terminal
```

## First steps after installing

1. Open **Settings → Intelligence Sources**.
2. Configure API keys (URLhaus and ThreatFox need **no** key and work
   immediately).
3. Until keys are configured, AegisX runs in clearly-labelled
   **Demonstration Mode** with sample data.

## Upgrading

```bash
sudo bash upgrade.sh            # re-run the idempotent installer
sudo bash upgrade.sh --backup   # archive user data to ~/aegisx-backup-<ts>.tar.gz first
```

Upgrades replace application files only — your configuration, database,
reports and logs live under your home directory and are never touched.

## Uninstallation

```bash
sudo bash uninstall.sh                  # remove app only
sudo bash uninstall.sh --purge-data     # also remove user data (asks 'PURGE')
sudo bash uninstall.sh --purge-data --yes  # skip the confirmation prompt
```

Removed by default: `/opt/AegisX`, `/usr/local/bin/aegisx`, the desktop
entry, and the system icon. **Preserved by default:** all user data.

## Manual user-data locations

| Content | Path |
| --- | --- |
| Configuration & key file | `~/.config/aegisx/` |
| Database, reports, exports | `~/.local/share/aegisx/` |
| Logs | `~/.local/state/aegisx/logs/aegisx.log` |
| Env overrides | `~/.config/aegisx/aegisx.env` (see `config.example.env`) |

## Running from source (no install)

```bash
bash run.sh                 # creates .venv/ in the project directory
aegisx --version            # only valid after installation
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `apt-get install` fails | Check connectivity; inspect `/var/log/aegisx-install.log`. |
| `pip` dependency install fails | Check network/proxy; re-run the installer (it is safe to re-run). |
| Blank window / Qt platform error | Ensure `libxcb-cursor0` etc. are installed — re-run `install.sh`. |
| Menu entry missing | Run `sudo update-desktop-database` and log out/in. |
| Launcher not found | Confirm `/usr/local/bin/aegisx` exists; re-run `install.sh`. |
