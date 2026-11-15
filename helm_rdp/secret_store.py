"""
Password storage backends (same model as Skiff SFTP and Porthole).

  none      passwords are never stored
  keyring   the desktop's Secret Service keychain (GNOME Keyring / KWallet)
            via libsecret. Unlocked with your login; works offline.
  vault     an encrypted file (AES-256-GCM, key derived from a master
            password with scrypt). Works anywhere, including headless and
            airgapped machines; unlocked once per app session.

Passwords are keyed by target, "TERMSRV/<computer>" like the Windows
Credential Manager. Nothing here ever writes a password to settings.json,
an .rdp file, logs, argv or the environment.

This module has no Qt dependency so it can be unit tested headless.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Dict, List, Optional, Tuple  # noqa: F401

from .config import atomic_write, config_dir

BACKEND_AUTO = "auto"
BACKEND_NONE = "none"
BACKEND_KEYRING = "keyring"
BACKEND_VAULT = "vault"
BACKENDS = (BACKEND_AUTO, BACKEND_NONE, BACKEND_KEYRING, BACKEND_VAULT)
BACKEND_LABELS = {
    BACKEND_AUTO: "Automatic: system keychain, or the encrypted vault if no keychain is running",
    BACKEND_NONE: "Don't save passwords",
    BACKEND_KEYRING: "System keychain (GNOME Keyring / Secret Service)",
    BACKEND_VAULT: "Encrypted vault file (master password)",
}
STORE_LABELS = {BACKEND_KEYRING: "system keychain", BACKEND_VAULT: "encrypted vault"}

MIN_MASTER_LEN = 8


class VaultError(Exception):
    pass


def default_vault_path() -> str:
    return os.path.join(config_dir(), "vault.json")


def vault_path_from_settings(settings: Dict) -> str:
    v = (settings.get("vault_file") or "").strip()
    return os.path.expanduser(v) if v else default_vault_path()


def normalize_backend(value) -> str:
    return value if value in BACKENDS else BACKEND_AUTO


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------
def backend_choices(keyring_available: bool, keyring_error: str = "") -> List[Tuple[str, str, bool]]:
    """(key, label, enabled) for the "Store passwords" list. The keychain is
    shown but disabled, with the reason, when no Secret Service is usable."""
    out = []
    for key in BACKENDS:
        label = BACKEND_LABELS[key]
        enabled = True
        if key == BACKEND_KEYRING and not keyring_available:
            enabled = False
            label += " — not available" + (": " + keyring_error if keyring_error else "")
        out.append((key, label, enabled))
    return out


def auto_backend(keyring_available: bool) -> str:
    """"Automatic": the system keychain when one is running, otherwise the
    encrypted vault (same rule Skiff uses when it moves passwords)."""
    return BACKEND_KEYRING if keyring_available else BACKEND_VAULT


def store_label(backend: str) -> Optional[str]:
    """Short name shown next to "Save password", or None when saving is off."""
    return STORE_LABELS.get(backend)


# ---------------------------------------------------------------------------
# Encrypted file vault
# ---------------------------------------------------------------------------
class FileVault:
    FORMAT = "helm-rdp-vault"
    VERSION = 1
    # scrypt cost: ~0.1-0.3 s on a desktop CPU, 32 MiB of memory.
    SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(str(path)))
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._data: Dict[str, str] = {}

    # --- state ------------------------------------------------------------
    @property
    def exists(self) -> bool:
        return os.path.isfile(self.path)

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def lock(self) -> None:
        self._key = None
        self._data = {}

    # --- crypto -----------------------------------------------------------
    @classmethod
    def _derive(cls, master: str, salt: bytes, n=None, r=None, p=None) -> bytes:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        kdf = Scrypt(salt=salt, length=32, n=int(n or cls.SCRYPT_N), r=int(r or cls.SCRYPT_R),
                     p=int(p or cls.SCRYPT_P), backend=default_backend())
        return kdf.derive(master.encode("utf-8"))

    def create(self, master: str) -> None:
        if self.exists:
            raise VaultError("A vault already exists at %s" % self.path)
        if len(master) < MIN_MASTER_LEN:
            raise VaultError("Master password must be at least %d characters" % MIN_MASTER_LEN)
        self._salt = os.urandom(16)
        self._key = self._derive(master, self._salt)
        self._data = {}
        self._write()

    def unlock(self, master: str) -> None:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                blob = json.load(fh)
            if blob.get("format") != self.FORMAT:
                raise VaultError("%s is not a Helm vault" % self.path)
            kdf = blob["kdf"]
            salt = base64.b64decode(kdf["salt"])
            nonce = base64.b64decode(blob["nonce"])
            ct = base64.b64decode(blob["ciphertext"])
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            raise VaultError("Cannot read vault %s: %s" % (self.path, e)) from e
        key = self._derive(master, salt, kdf.get("n"), kdf.get("r"), kdf.get("p"))
        try:
            plain = AESGCM(key).decrypt(nonce, ct, self.FORMAT.encode())
        except InvalidTag:
            raise VaultError("Wrong master password (or the vault file was modified).")
        self._data = json.loads(plain.decode("utf-8"))
        self._key, self._salt = key, salt

    def change_master(self, old: str, new: str) -> None:
        if len(new) < MIN_MASTER_LEN:
            raise VaultError("Master password must be at least %d characters" % MIN_MASTER_LEN)
        self.unlock(old)
        self._salt = os.urandom(16)
        self._key = self._derive(new, self._salt)
        self._write()

    def _write(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        assert self._key is not None and self._salt is not None
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(
            nonce, json.dumps(self._data).encode("utf-8"), self.FORMAT.encode())
        blob = {
            "format": self.FORMAT, "version": self.VERSION, "cipher": "AES-256-GCM",
            "kdf": {"name": "scrypt", "n": self.SCRYPT_N, "r": self.SCRYPT_R,
                    "p": self.SCRYPT_P, "salt": base64.b64encode(self._salt).decode()},
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }
        atomic_write(self.path, json.dumps(blob, indent=2), backup=True)

    # --- secrets ----------------------------------------------------------
    def _need_unlocked(self):
        if not self.unlocked:
            raise VaultError("The vault is locked.")

    def get(self, target: str) -> Optional[str]:
        self._need_unlocked()
        return self._data.get(target)

    def set(self, target: str, password: str, label: str = "") -> None:
        self._need_unlocked()
        self._data[target] = password
        self._write()

    def delete(self, target: str) -> None:
        self._need_unlocked()
        if self._data.pop(target, None) is not None:
            self._write()

    def ids(self):
        self._need_unlocked()
        return list(self._data)


# ---------------------------------------------------------------------------
# Secret Service keychain
# ---------------------------------------------------------------------------
class KeyringStore:
    SCHEMA_NAME = "us.andersoncomputer.HelmRDP.Password"

    def __init__(self):
        self._schema = None
        self.error: Optional[str] = None
        try:
            import gi
            gi.require_version("Secret", "1")
            from gi.repository import Secret
            self._Secret = Secret
            self._schema = Secret.Schema.new(
                self.SCHEMA_NAME, Secret.SchemaFlags.NONE,
                {"target": Secret.SchemaAttributeType.STRING})
        except (ImportError, ValueError, AttributeError) as e:
            self.error = "libsecret is not available: %s" % e

    @property
    def available(self) -> bool:
        if self._schema is None:
            return False
        try:
            from gi.repository import Gio, GLib
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            res = bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                "org.freedesktop.DBus", "NameHasOwner",
                                GLib.Variant("(s)", ("org.freedesktop.secrets",)),
                                None, Gio.DBusCallFlags.NONE, 2000, None)
            if res.unpack()[0]:
                return True
            # Activatable but not yet running also counts.
            res = bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                "org.freedesktop.DBus", "ListActivatableNames",
                                None, None, Gio.DBusCallFlags.NONE, 2000, None)
            if "org.freedesktop.secrets" in res.unpack()[0]:
                return True
            self.error = ("No Secret Service (GNOME Keyring/KWallet) is running "
                          "in this session.")
            return False
        except Exception as e:  # no session bus, etc.
            self.error = str(e) or "No D-Bus session bus."
            return False

    def get(self, target: str) -> Optional[str]:
        try:
            return self._Secret.password_lookup_sync(self._schema, {"target": target}, None)
        except Exception as e:
            raise VaultError("Keychain lookup failed: %s" % e) from e

    def set(self, target: str, password: str, label: str = "") -> None:
        try:
            ok = self._Secret.password_store_sync(
                self._schema, {"target": target}, self._Secret.COLLECTION_DEFAULT,
                label or "Helm Remote Desktop (%s)" % target, password, None)
        except Exception as e:
            raise VaultError("Keychain store failed: %s" % e) from e
        if not ok:
            raise VaultError("The keychain refused to store the password.")

    def delete(self, target: str) -> None:
        try:
            self._Secret.password_clear_sync(self._schema, {"target": target}, None)
        except Exception as e:
            raise VaultError("Keychain delete failed: %s" % e) from e


def target_name(host: str) -> str:
    """Credential target for a computer, the same form mstsc uses."""
    return "TERMSRV/%s" % (host or "").strip().lower()


def keyring_label(host: str, username: str) -> str:
    return "Helm Remote Desktop: %s@%s" % (username or "?", host)
