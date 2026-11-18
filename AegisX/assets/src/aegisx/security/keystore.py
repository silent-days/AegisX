"""
AegisX — secure provider credential storage.

Storage strategy (best available wins):
  1. System keyring (``keyring`` package) when installed.
  2. Local encrypted-at-rest file: ~/.config/aegisx/keys.json, sealed with a
     stream cipher derived from /etc/machine-id, permissions 0600.

The fallback file is explicitly documented as obfuscation, not OS-level
protection — the Settings UI communicates this to the analyst.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import stat
from pathlib import Path

from ..utils.paths import config_dir

log = logging.getLogger("aegisx.security")

SERVICE = "aegisx"
_KEY_FILE = "keys.json"

# Providers that require an API key to return live results.
KEY_PROVIDERS = ("abuseipdb", "otx", "virustotal", "threatfox", "urlhaus")

try:  # pragma: no cover - environment dependent
    import keyring  # type: ignore

    _HAS_KEYRING = True
except Exception:  # noqa: BLE001
    keyring = None  # type: ignore
    _HAS_KEYRING = False


# ---------------------------------------------------------------------------
# file fallback with machine-id derived stream cipher
# ---------------------------------------------------------------------------

def _machine_key() -> bytes:
    """Derive a stable 32-byte local key from the machine id + username."""
    seed = ""
    for cand in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            seed = Path(cand).read_text(encoding="utf-8").strip()
            if seed:
                break
        except OSError:
            continue
    if not seed:
        seed = "aegisx-fallback"
    seed += os.environ.get("USER", "user")
    raw = bytearray(32)
    acc = 0x9E3779B9
    for i in range(32):
        acc = (acc * 1103515245 + 12345 + ord(seed[i % len(seed)])) & 0x7FFFFFFF
        raw[i] = (acc >> 7) & 0xFF
    return bytes(raw)


def _xor_stream(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _load_file_store() -> dict:
    path = config_dir() / _KEY_FILE
    try:
        if not path.is_file():
            return {}
        blob = json.loads(path.read_text(encoding="utf-8"))
        payload = base64.b64decode(blob.get("data", ""))
        plain = _xor_stream(payload, _machine_key())
        return json.loads(plain.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        log.warning("Key store unreadable (%s); starting clean.", e)
        return {}


def _save_file_store(store: dict) -> None:
    path = config_dir() / _KEY_FILE
    payload = _xor_stream(json.dumps(store).encode("utf-8"), _machine_key())
    blob = {"version": 1, "backend": "file", "data": base64.b64encode(payload).decode("ascii")}
    path.write_text(json.dumps(blob, indent=2), encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

class KeyStore:
    """Stores provider API credentials securely."""

    def __init__(self) -> None:
        self.backend = "keyring" if _HAS_KEYRING else "file"
        if not _HAS_KEYRING:
            log.info(
                "keyring package not available — using permission-restricted "
                "local key file (%s). Install 'keyring' for system-grade storage.",
                config_dir() / _KEY_FILE,
            )

    # -- basic -------------------------------------------------------------
    def get_key(self, provider: str) -> str:
        provider = provider.lower()
        if _HAS_KEYRING:
            try:
                value = keyring.get_password(SERVICE, provider)  # type: ignore[union-attr]
                if value:
                    return value
            except Exception as e:  # noqa: BLE001
                log.debug("keyring read failed for %s: %s", provider, e)
        return _load_file_store().get(provider, "")

    def set_key(self, provider: str, value: str) -> None:
        provider = provider.lower()
        value = (value or "").strip()
        if _HAS_KEYRING:
            try:
                if value:
                    keyring.set_password(SERVICE, provider, value)  # type: ignore[union-attr]
                else:
                    self.delete_key(provider)
                return
            except Exception as e:  # noqa: BLE001
                log.warning("keyring write failed for %s (%s); using file fallback.", provider, e)
        store = _load_file_store()
        if value:
            store[provider] = value
        else:
            store.pop(provider, None)
        _save_file_store(store)

    def delete_key(self, provider: str) -> None:
        provider = provider.lower()
        if _HAS_KEYRING:
            try:
                keyring.delete_password(SERVICE, provider)  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass
        store = _load_file_store()
        store.pop(provider, None)
        _save_file_store(store)

    def has_key(self, provider: str) -> bool:
        return bool(self.get_key(provider))

    def configured_providers(self) -> list[str]:
        return [p for p in KEY_PROVIDERS if self.has_key(p)]

    def backend_description(self) -> str:
        if self.backend == "keyring":
            return "System keyring (encrypted)"
        return "Local encrypted file (~/.config/aegisx/keys.json, mode 0600)"
