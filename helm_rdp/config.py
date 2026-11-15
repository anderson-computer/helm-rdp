"""Settings under ~/.config/helm-rdp/ and the master configuration file.

  /etc/helm-rdp/helm-rdp.conf        master configuration (INI, [helm-rdp])
  ~/.config/helm-rdp/helm-rdp.conf   per-user override, same keys
  ~/.config/helm-rdp/settings.json   recent computers, password store choice
  ~/.config/helm-rdp/Default.rdp     the last connection settings (like
                                     Documents\\Default.rdp for mstsc)
  ~/.config/helm-rdp/known_certs.json  server certificates you accepted
  ~/.config/helm-rdp/vault.json      encrypted password vault, if used

No password is ever written to any of these except, encrypted, vault.json.
"""

from __future__ import annotations

import configparser
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List

APP_DIR_NAME = "helm-rdp"
SETTINGS_FILE = "settings.json"
DEFAULT_RDP = "Default.rdp"
KNOWN_CERTS = "known_certs.json"
MASTER_CONF = "/etc/helm-rdp/helm-rdp.conf"
MAX_RECENT = 10


def config_dir() -> str:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = xdg if xdg else os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(base, APP_DIR_NAME)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def settings_path() -> str:
    return os.path.join(config_dir(), SETTINGS_FILE)


def default_rdp_path() -> str:
    return os.path.join(config_dir(), DEFAULT_RDP)


def known_certs_path() -> str:
    return os.path.join(config_dir(), KNOWN_CERTS)


def user_conf_path() -> str:
    return os.path.join(config_dir(), "helm-rdp.conf")


def atomic_write(path: str, text, backup: bool = False, mode: int = 0o600) -> None:
    """Write text (str) or bytes to path atomically, private from the start.
    With backup=True the previous version is kept as path.bak."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if backup and os.path.exists(path):
        try:
            shutil.copy2(path, path + ".bak")
            os.chmod(path + ".bak", 0o600)
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=folder)
    try:
        data = text.encode("utf-8") if isinstance(text, str) else text
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# settings.json
# ---------------------------------------------------------------------------
def default_settings() -> Dict[str, Any]:
    return {
        "recent": [],                 # [{"host": "pc01", "username": "DOMAIN\\mike"}]
        "password_backend": "auto",   # auto | none | keyring | vault
        "vault_file": "",             # "" = ~/.config/helm-rdp/vault.json
        "show_options": False,
        "last_tab": 0,
        "last_dir": "",
    }


def load_settings() -> Dict[str, Any]:
    out = default_settings()
    try:
        with open(settings_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            out.update(data)
    except (OSError, ValueError):
        pass
    if not isinstance(out.get("recent"), list):
        out["recent"] = []
    return out


def save_settings(settings: Dict[str, Any]) -> None:
    clean = {k: v for k, v in settings.items() if k != "password"}
    atomic_write(settings_path(), json.dumps(clean, indent=2, sort_keys=True))


def add_recent(settings: Dict[str, Any], host: str, username: str = "") -> List[Dict[str, str]]:
    """Most recent first, one entry per computer (case-insensitive), like the
    mstsc Computer drop-down. Remembers the user name used for that computer."""
    host = (host or "").strip()
    if not host:
        return settings.get("recent", [])
    recent = [r for r in settings.get("recent", [])
              if isinstance(r, dict) and r.get("host", "").lower() != host.lower()]
    recent.insert(0, {"host": host, "username": username or ""})
    settings["recent"] = recent[:MAX_RECENT]
    return settings["recent"]


def remove_recent(settings: Dict[str, Any], host: str) -> None:
    settings["recent"] = [r for r in settings.get("recent", [])
                          if r.get("host", "").lower() != (host or "").lower()]


def recent_username(settings: Dict[str, Any], host: str) -> str:
    for r in settings.get("recent", []):
        if r.get("host", "").lower() == (host or "").strip().lower():
            return r.get("username", "")
    return ""


# ---------------------------------------------------------------------------
# Master configuration (INI)
# ---------------------------------------------------------------------------
MASTER_DEFAULTS = {
    # FreeRDP client: auto (xfreerdp3, xfreerdp, sdl-freerdp3, wlfreerdp) or a path.
    "freerdp": "auto",
    # Extra FreeRDP options appended to every connection (no passwords here).
    "extra_args": "",
    # FreeRDP log level passed with /log-level: (Helm needs INFO to see
    # when the session is up; WARN keeps the log quieter).
    "log_level": "INFO",
    # Seconds to wait for the server before giving up (TCP connect, cert check).
    "connect_timeout": "15",
    # Where Help > About links and the Sonar/Porthole hand-off look for Helm.
    "default_port": "3389",
}


def load_master(paths=None) -> Dict[str, str]:
    """Master config, then the per-user override. Unknown keys are kept."""
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict({"helm-rdp": MASTER_DEFAULTS})
    if paths is None:
        paths = [os.environ.get("HELM_RDP_CONF") or MASTER_CONF]
        try:
            paths.append(user_conf_path())
        except OSError:
            pass
    for p in paths:
        try:
            cp.read(p, encoding="utf-8")
        except (OSError, configparser.Error):
            pass
    return dict(cp["helm-rdp"])
