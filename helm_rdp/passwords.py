"""Saved passwords: Qt dialogs and the glue between the UI and secret_store.

Same model and wording as Skiff SFTP and Porthole: the system keychain
(GNOME Keyring / KWallet through the Secret Service) first, an encrypted
vault file (AES-256-GCM, master password) when no keychain is running.
Passwords are keyed by "TERMSRV/<computer>" like the Windows Credential
Manager. settings.json only records which computers have a saved password
and in which store - never the password.
"""

from __future__ import annotations

import html
import os
from typing import Callable, Dict, Optional, Tuple

from .config import save_settings
from .qtcompat import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
    exec_,
    qenum,
)
from .secret_store import (
    BACKEND_AUTO,
    BACKEND_KEYRING,
    BACKEND_NONE,
    BACKEND_VAULT,
    MIN_MASTER_LEN,
    STORE_LABELS,
    FileVault,
    KeyringStore,
    VaultError,
    auto_backend,
    backend_choices,
    default_vault_path,
    keyring_label,
    normalize_backend,
    target_name,
    vault_path_from_settings,
)


def _dim(label: QLabel) -> QLabel:
    label.setEnabled(False)
    return label


def _note(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    return _dim(lbl)


def _accepted(code) -> bool:
    return code == qenum(QDialog, "Accepted") or code == 1


class MasterPasswordDialog(QDialog):
    """mode: "create", "unlock" or "change"."""

    TITLES = {"create": "Create Password Vault", "unlock": "Unlock Password Vault",
              "change": "Change Master Password"}
    INTRO = {
        "create": "Choose a master password for your new vault. It encrypts every "
                  "saved password and cannot be recovered if forgotten.",
        "unlock": "Enter the master password to unlock saved passwords "
                  "for this session.",
        "change": "Enter the current master password and a new one.",
    }

    def __init__(self, parent, mode: str, vault_path: str, message: str = ""):
        super().__init__(parent)
        self.mode = mode
        self.setWindowTitle(self.TITLES[mode])
        self.setModal(True)
        self.setMinimumWidth(440)
        box = QVBoxLayout(self)
        intro = QLabel(self.INTRO[mode])
        intro.setWordWrap(True)
        box.addWidget(intro)
        path_lbl = _dim(QLabel(vault_path))
        path_lbl.setWordWrap(True)
        box.addWidget(path_lbl)
        self.message = QLabel("")
        if message:
            self.message.setText("<span style='color:#c42b1c'>%s</span>" % html.escape(message))
            self.message.setWordWrap(True)
            box.addWidget(self.message)

        def pw(placeholder):
            e = QLineEdit()
            e.setEchoMode(qenum(QLineEdit, "Password"))
            e.setPlaceholderText(placeholder)
            e.textChanged.connect(lambda _t: self._validate())
            box.addWidget(e)
            return e

        self.current = pw("Current master password") if mode in ("unlock", "change") else None
        if mode in ("create", "change"):
            self.new1 = pw("New master password (min. %d characters)" % MIN_MASTER_LEN)
            self.new2 = pw("Repeat new master password")
        else:
            self.new1 = self.new2 = None
        self.hint = _dim(QLabel(""))
        box.addWidget(self.hint)
        buttons = QDialogButtonBox()
        self.ok = buttons.addButton("Unlock" if mode == "unlock" else "Save",
                                    qenum(QDialogButtonBox, "AcceptRole"))
        buttons.addButton(qenum(QDialogButtonBox, "Cancel"))
        self.ok.setDefault(True)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        box.addWidget(buttons)
        self._validate()

    def _validate(self) -> None:
        ok, hint = True, ""
        if self.current is not None and not self.current.text():
            ok = False
        if self.new1 is not None:
            a, b = self.new1.text(), self.new2.text()
            if len(a) < MIN_MASTER_LEN:
                ok, hint = False, "At least %d characters." % MIN_MASTER_LEN
            elif a != b:
                ok, hint = False, "Passwords don't match."
        self.hint.setText(hint)
        self.ok.setEnabled(ok)

    def current_password(self) -> str:
        return self.current.text() if self.current else ""

    def new_password(self) -> str:
        return self.new1.text() if self.new1 else ""


class PasswordOptionsDialog(QDialog):
    """Options ▸ Passwords: where saved passwords are kept."""

    def __init__(self, parent, settings: Dict, keyring_available: bool, keyring_error: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Options — Passwords")
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.backend = QComboBox()
        for key, label, enabled in backend_choices(keyring_available, keyring_error):
            self.backend.addItem(label, key)
            item = self.backend.model().item(self.backend.count() - 1)
            if item is not None and not enabled:
                item.setEnabled(False)
        idx = self.backend.findData(normalize_backend(settings.get("password_backend")))
        self.backend.setCurrentIndex(max(0, idx))
        form.addRow("Store passwords", self.backend)
        row = QWidget()
        rl = QHBoxLayout(row)
        rl.setContentsMargins(0, 0, 0, 0)
        self.vault_entry = QLineEdit(vault_path_from_settings(settings))
        self.vault_browse = QPushButton("Browse…")
        self.vault_default = QPushButton("Default")
        rl.addWidget(self.vault_entry, 1)
        rl.addWidget(self.vault_browse)
        rl.addWidget(self.vault_default)
        form.addRow("Vault file", row)
        self.change_master_btn = QPushButton("Change Master Password…")
        form.addRow("", self.change_master_btn)
        layout.addLayout(form)
        self.status = _note("")
        layout.addWidget(self.status)
        layout.addWidget(_note(
            "Keychain: stored in your login keyring, unlocked when you log in. "
            "Vault: an AES-256 encrypted file, unlocked with a master password "
            "once per session — works without a desktop keyring. Saved "
            "passwords are handed to FreeRDP through a private pipe and are never "
            "written to .rdp files, settings.json, the command line or the environment. "
            "Changing the store applies to passwords you save from now on."))
        buttons = QDialogButtonBox(flags_ok_cancel())
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.keyring_available = keyring_available
        self.vault_browse.clicked.connect(self._browse)
        self.vault_default.clicked.connect(lambda: self.vault_entry.setText(default_vault_path()))
        self.backend.currentIndexChanged.connect(lambda _i: self._sync())
        self._sync()

    def _browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Choose vault file", self.vault_path(),
                                              "Vault (*.json);;All files (*)")
        if path:
            self.vault_entry.setText(path)

    def _sync(self) -> None:
        b = self.selected_backend()
        eff = auto_backend(self.keyring_available) if b == BACKEND_AUTO else b
        is_vault = eff == BACKEND_VAULT
        for w in (self.vault_entry, self.vault_browse, self.vault_default, self.change_master_btn):
            w.setEnabled(is_vault)
        self.status.setText({BACKEND_KEYRING: "Passwords you save go to the system keychain.",
                             BACKEND_VAULT: "Passwords you save go to the encrypted vault.",
                             BACKEND_NONE: "Passwords are never saved; you type them at every connection."}[eff])

    def selected_backend(self) -> str:
        return normalize_backend(self.backend.currentData())

    def vault_path(self) -> str:
        text = self.vault_entry.text().strip()
        return os.path.abspath(os.path.expanduser(text)) if text else default_vault_path()


def flags_ok_cancel():
    return qenum(QDialogButtonBox, "Ok") | qenum(QDialogButtonBox, "Cancel")


class PasswordManager:
    """Keychain / vault access with the prompts it needs."""

    def __init__(self, parent: Optional[QWidget], settings: Dict,
                 status: Optional[Callable[[str], None]] = None):
        self.parent = parent
        self.settings = settings
        self.status = status or (lambda _m: None)
        self._keyring: Optional[KeyringStore] = None
        self._vault: Optional[FileVault] = None

    # --- stores ---------------------------------------------------------------
    def keyring(self) -> KeyringStore:
        if self._keyring is None:
            self._keyring = KeyringStore()
        return self._keyring

    def vault_path(self) -> str:
        return vault_path_from_settings(self.settings)

    def vault(self) -> FileVault:
        if self._vault is None or self._vault.path != os.path.abspath(self.vault_path()):
            self._vault = FileVault(self.vault_path())
        return self._vault

    def effective_backend(self) -> str:
        b = normalize_backend(self.settings.get("password_backend"))
        if b == BACKEND_AUTO:
            return auto_backend(self.keyring().available)
        return b

    def store_label(self) -> Optional[str]:
        return STORE_LABELS.get(self.effective_backend())

    def vault_unlocked(self) -> bool:
        return self._vault is not None and self._vault.unlocked

    def _open(self, backend: str, create: bool):
        if backend == BACKEND_KEYRING:
            ring = self.keyring()
            if not ring.available:
                raise VaultError("System keychain not available: " + (
                    ring.error or "No Secret Service (GNOME Keyring/KWallet) is running in this session."))
            return ring
        if backend == BACKEND_VAULT:
            v = self.vault()
            if v.unlocked:
                return v
            if not v.exists:
                if not create:
                    return None
                dlg = MasterPasswordDialog(self.parent, "create", v.path)
                if not _accepted(exec_(dlg)):
                    return None
                v.create(dlg.new_password())
                self.status("Password vault created.")
                return v
            message = ""
            for _ in range(3):
                dlg = MasterPasswordDialog(self.parent, "unlock", v.path, message)
                if not _accepted(exec_(dlg)):
                    return None
                try:
                    v.unlock(dlg.current_password())
                    return v
                except VaultError as e:
                    message = str(e)
            raise VaultError(message or "The vault could not be unlocked.")
        return None

    # --- index (no secrets) -----------------------------------------------------
    def _index(self) -> Dict[str, Dict]:
        idx = self.settings.setdefault("saved_targets", {})
        if not isinstance(idx, dict):
            idx = self.settings["saved_targets"] = {}
        return idx

    def saved_entry(self, host: str) -> Optional[Dict]:
        return self._index().get(target_name(host))

    def has_saved(self, host: str) -> bool:
        return self.saved_entry(host) is not None

    def _persist(self) -> None:
        try:
            save_settings(self.settings)
        except OSError as e:
            self.error("Could not save options", str(e))

    # --- API --------------------------------------------------------------------
    def get(self, host: str) -> Tuple[Optional[str], str]:
        """(password or None, username it was saved with)."""
        entry = self.saved_entry(host)
        if not entry:
            return None, ""
        try:
            store = self._open(entry.get("store", BACKEND_KEYRING), create=False)
            if store is None:
                return None, entry.get("username", "")
            return store.get(target_name(host)), entry.get("username", "")
        except VaultError as e:
            self.error("Saved password unavailable", str(e))
            return None, entry.get("username", "")

    def save(self, host: str, username: str, password: str) -> bool:
        backend = self.effective_backend()
        if backend == BACKEND_NONE:
            return False
        try:
            store = self._open(backend, create=True)
            if store is None:
                return False
            old = self.saved_entry(host)
            if old and old.get("store") != backend:
                self.forget(host, quiet=True)
            store.set(target_name(host), password, keyring_label(host, username))
        except VaultError as e:
            self.error("Could not save the password", str(e))
            return False
        self._index()[target_name(host)] = {"username": username, "store": backend}
        self._persist()
        self.status("Password for %s saved in the %s." % (host, STORE_LABELS[backend]))
        return True

    def forget(self, host: str, quiet: bool = False) -> bool:
        entry = self.saved_entry(host)
        if not entry:
            return False
        try:
            store = self._open(entry.get("store", BACKEND_KEYRING), create=False)
            if store is not None:
                store.delete(target_name(host))
        except VaultError as e:
            if not quiet:
                self.error("Could not remove the saved password", str(e))
            return False
        self._index().pop(target_name(host), None)
        self._persist()
        if not quiet:
            self.status("Saved credentials for %s deleted." % host)
        return True

    def lock_vault(self) -> bool:
        if self._vault is not None and self._vault.unlocked:
            self._vault.lock()
            self.status("Password vault locked.")
            return True
        self.status("The password vault is not unlocked.")
        return False

    def change_master(self, path: Optional[str] = None) -> bool:
        v = FileVault(path or self.vault_path())
        if not v.exists:
            self.error("No vault yet", "A vault is created the first time you save a password.")
            return False
        message = ""
        for _ in range(3):
            dlg = MasterPasswordDialog(self.parent, "change", v.path, message)
            if not _accepted(exec_(dlg)):
                return False
            try:
                v.change_master(dlg.current_password(), dlg.new_password())
                self._vault = v
                self.status("Master password changed.")
                return True
            except VaultError as e:
                message = str(e)
        return False

    def error(self, title: str, text: str) -> None:
        QMessageBox.warning(self.parent, title, text)
