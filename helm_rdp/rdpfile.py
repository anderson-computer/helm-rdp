"""Read and write Microsoft Remote Desktop Connection (.rdp) files.

An .rdp file is one setting per line, "name:type:value", where type is
i (integer), s (string) or b (binary, hex). mstsc writes UTF-16 LE with a
byte-order mark and CRLF line ends; Helm writes the same so the files open
in mstsc on Windows, and reads UTF-16 or UTF-8.

RdpProfile keeps every line it read, including ones Helm does not use, in
their original order, so opening and saving a file from Windows does not
drop anything. Saved passwords ("password 51:b:", a Windows DPAPI blob that
only the Windows user who made it can decrypt) are ignored on read and never
written.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Tuple

_LINE = re.compile(r"^\s*([^:\r\n]+?)\s*:\s*([isbISB])\s*:(.*)$")

# Never read or written: secrets stored by Windows.
SECRET_KEYS = {"password 51", "password", "clear password", "gatewaypassword"}

# mstsc defaults (what a fresh Default.rdp contains), plus Linux-only keys
# Helm adds. Order follows mstsc's Default.rdp.
DEFAULTS: List[Tuple[str, str, object]] = [
    ("screen mode id", "i", 2),             # 1 window, 2 full screen
    ("use multimon", "i", 0),
    ("desktopwidth", "i", 1920),
    ("desktopheight", "i", 1080),
    ("session bpp", "i", 32),
    ("compression", "i", 1),
    ("keyboardhook", "i", 2),               # 0 local, 1 remote, 2 full screen only
    ("audiocapturemode", "i", 0),           # 0 don't record, 1 record from this computer
    ("videoplaybackmode", "i", 1),
    ("connection type", "i", 7),            # 1 modem .. 6 LAN, 7 auto-detect
    ("networkautodetect", "i", 1),
    ("bandwidthautodetect", "i", 1),
    ("displayconnectionbar", "i", 1),
    ("enableworkspacereconnect", "i", 0),
    ("disable wallpaper", "i", 0),
    ("allow font smoothing", "i", 1),
    ("allow desktop composition", "i", 1),
    ("disable full window drag", "i", 0),
    ("disable menu anims", "i", 0),
    ("disable themes", "i", 0),
    ("disable cursor setting", "i", 0),
    ("bitmapcachepersistenable", "i", 1),
    ("full address", "s", ""),
    ("audiomode", "i", 0),                  # 0 this computer, 1 remote, 2 don't play
    ("redirectprinters", "i", 0),
    ("redirectcomports", "i", 0),
    ("redirectsmartcards", "i", 0),
    ("redirectclipboard", "i", 1),
    ("redirectposdevices", "i", 0),
    ("drivestoredirect", "s", ""),
    ("autoreconnection enabled", "i", 1),
    ("authentication level", "i", 2),       # 0 connect, 1 do not connect, 2 warn
    ("prompt for credentials", "i", 0),
    ("negotiate security layer", "i", 1),
    ("remoteapplicationmode", "i", 0),
    ("alternate shell", "s", ""),
    ("shell working directory", "s", ""),
    ("gatewayhostname", "s", ""),
    ("gatewayusagemethod", "i", 4),         # 0 none, 1 always, 2 bypass local, 4 auto-detect
    ("gatewaycredentialssource", "i", 4),   # 0 ask (NTLM), 4 select later
    ("gatewayprofileusagemethod", "i", 0),  # 0 automatic (default), 1 explicit settings
    ("promptcredentialonce", "i", 0),       # use gateway credentials for the computer
    ("gatewaybrokeringtype", "i", 0),
    ("use redirection server name", "i", 0),
    ("rdgiskdcproxy", "i", 0),
    ("kdcproxyname", "s", ""),
    ("username", "s", ""),
]

DEFAULT_PORT = 3389

# Experience tab: what each "connection type" preset turns on, in the order
# (desktop background, font smoothing, desktop composition, show window
# contents while dragging, menu and window animation, visual styles,
# persistent bitmap caching). Same as mstsc.
EXPERIENCE_KEYS = [
    ("disable wallpaper", True),            # True: the key is a "disable" flag
    ("allow font smoothing", False),
    ("allow desktop composition", False),
    ("disable full window drag", True),
    ("disable menu anims", True),
    ("disable themes", True),
    ("bitmapcachepersistenable", False),
]
CONNECTION_PRESETS = {
    1: (0, 0, 0, 0, 0, 0, 1),   # Modem (56 Kbps)
    2: (0, 0, 0, 0, 0, 1, 1),   # Low-speed broadband (256 Kbps - 2 Mbps)
    3: (0, 0, 1, 0, 0, 1, 1),   # Satellite (2 Mbps - 16 Mbps with high latency)
    4: (0, 0, 1, 1, 1, 1, 1),   # High-speed broadband (2 Mbps - 10 Mbps)
    5: (1, 1, 1, 1, 1, 1, 1),   # WAN (10 Mbps or higher with high latency)
    6: (1, 1, 1, 1, 1, 1, 1),   # LAN (10 Mbps or higher)
    7: (1, 1, 1, 1, 1, 1, 1),   # Detect connection quality automatically
}
CONNECTION_TYPES = [
    (1, "Modem (56 Kbps)"),
    (2, "Low-speed broadband (256 Kbps - 2 Mbps)"),
    (3, "Satellite (2 Mbps - 16 Mbps with high latency)"),
    (4, "High-speed broadband (2 Mbps - 10 Mbps)"),
    (5, "WAN (10 Mbps or higher with high latency)"),
    (6, "LAN (10 Mbps or higher)"),
    (7, "Detect connection quality automatically"),
]


class RdpFileError(Exception):
    pass


class RdpProfile:
    """Ordered name -> (type, value) map with mstsc defaults."""

    def __init__(self, defaults: bool = True):
        self._items: "OrderedDict[str, Tuple[str, object]]" = OrderedDict()
        if defaults:
            for name, typ, value in DEFAULTS:
                self._items[name] = (typ, value)

    # --- access -----------------------------------------------------------
    def get(self, name: str, default=None):
        item = self._items.get(name.lower())
        return default if item is None else item[1]

    def get_int(self, name: str, default: int = 0) -> int:
        try:
            return int(self.get(name, default))
        except (TypeError, ValueError):
            return default

    def get_str(self, name: str, default: str = "") -> str:
        v = self.get(name, default)
        return default if v is None else str(v)

    def get_bool(self, name: str, default: bool = False) -> bool:
        return self.get_int(name, 1 if default else 0) != 0

    def set(self, name: str, value, typ: Optional[str] = None) -> None:
        name = name.lower()
        if name in SECRET_KEYS:
            return
        if typ is None:
            typ = self._items.get(name, ("i" if isinstance(value, (bool, int)) else "s", None))[0]
        if typ == "i":
            value = int(value)
        self._items[name] = (typ, value)

    def remove(self, name: str) -> None:
        self._items.pop(name.lower(), None)

    def names(self) -> List[str]:
        return list(self._items)

    def items(self) -> Iterable[Tuple[str, str, object]]:
        for name, (typ, value) in self._items.items():
            yield name, typ, value

    def copy(self) -> "RdpProfile":
        out = RdpProfile(defaults=False)
        out._items = OrderedDict(self._items)
        return out

    def __eq__(self, other) -> bool:
        return isinstance(other, RdpProfile) and list(self.items()) == list(other.items())

    # --- convenience ------------------------------------------------------
    @property
    def address(self) -> Tuple[str, int]:
        """(host, port) from "full address" (and "server port")."""
        host, port = split_address(self.get_str("full address"))
        if port is None:
            port = self.get_int("server port", DEFAULT_PORT) or DEFAULT_PORT
        return host, port

    def set_address(self, text: str) -> None:
        self.set("full address", (text or "").strip(), "s")
        self.remove("server port")

    def apply_connection_type(self, ctype: int) -> None:
        preset = CONNECTION_PRESETS.get(int(ctype))
        if preset is None:
            return
        self.set("connection type", int(ctype), "i")
        self.set("networkautodetect", 1 if ctype == 7 else 0, "i")
        self.set("bandwidthautodetect", 1 if ctype == 7 else 0, "i")
        for (key, inverted), on in zip(EXPERIENCE_KEYS, preset):
            self.set(key, (0 if on else 1) if inverted else (1 if on else 0), "i")

    def experience(self) -> List[bool]:
        out = []
        for key, inverted in EXPERIENCE_KEYS:
            v = self.get_bool(key)
            out.append(not v if inverted else v)
        return out

    def set_experience(self, flags: List[bool]) -> None:
        for (key, inverted), on in zip(EXPERIENCE_KEYS, flags):
            self.set(key, (0 if on else 1) if inverted else (1 if on else 0), "i")

    def drives(self) -> List[str]:
        """Local folders to redirect ("drivestoredirect"). '*' means all."""
        raw = self.get_str("drivestoredirect")
        return [d for d in (p.strip() for p in raw.split(";")) if d]

    def set_drives(self, drives: List[str]) -> None:
        self.set("drivestoredirect", ";".join(d for d in drives if d) + (";" if drives else ""), "s")

    # --- text -------------------------------------------------------------
    def to_text(self) -> str:
        lines = []
        for name, typ, value in self.items():
            if name in SECRET_KEYS:
                continue
            lines.append("%s:%s:%s" % (name, typ, value))
        return "\r\n".join(lines) + "\r\n"

    @classmethod
    def from_text(cls, text: str, defaults: bool = True) -> "RdpProfile":
        prof = cls(defaults=defaults)
        seen = 0
        for raw in text.splitlines():
            line = raw.strip().lstrip("\ufeff")
            if not line:
                continue
            m = _LINE.match(line)
            if not m:
                continue
            name, typ, value = m.group(1).strip().lower(), m.group(2).lower(), m.group(3)
            if name in SECRET_KEYS:
                continue
            if typ == "i":
                try:
                    value = int(value.strip())
                except ValueError:
                    continue
            prof._items[name] = (typ, value)
            seen += 1
        if not seen and text.strip():
            raise RdpFileError("This is not a Remote Desktop (.rdp) file.")
        return prof


def decode_rdp_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8")
    if len(data) > 1 and data[1:2] == b"\x00":
        return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def load_rdp(path: str) -> RdpProfile:
    try:
        with open(path, "rb") as fh:
            data = fh.read(1024 * 1024 + 1)
    except OSError as e:
        raise RdpFileError("Cannot open %s: %s" % (path, e.strerror or e)) from e
    if len(data) > 1024 * 1024:
        raise RdpFileError("%s is too large to be an .rdp file." % path)
    return RdpProfile.from_text(decode_rdp_bytes(data))


def save_rdp(profile: RdpProfile, path: str) -> None:
    """UTF-16 LE with BOM and CRLF, as mstsc writes it."""
    from .config import atomic_write
    atomic_write(path, b"\xff\xfe" + profile.to_text().encode("utf-16-le"), mode=0o600)


def split_address(text: str) -> Tuple[str, Optional[int]]:
    """'pc01' / 'pc01:3390' / '10.0.0.5:3390' / '[fe80::1]:3390' / 'fe80::1'."""
    text = (text or "").strip()
    if text.lower().startswith("rdp://"):
        text = text[6:].split("/", 1)[0]
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            host, rest = text[1:end], text[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, _port(rest[1:])
            return host, None
    if text.count(":") == 1:
        host, port = text.split(":", 1)
        if port.isdigit():
            return host, _port(port)
    return text, None


def _port(text: str) -> Optional[int]:
    p = int(text)
    return p if 0 < p < 65536 else None


def join_address(host: str, port: int) -> str:
    if not port or int(port) == DEFAULT_PORT:
        return host
    if ":" in host:
        return "[%s]:%d" % (host, int(port))
    return "%s:%d" % (host, int(port))


def split_user(text: str) -> Tuple[str, str]:
    """'DOMAIN\\user' -> ('DOMAIN', 'user'); 'user@domain' stays as the user."""
    text = (text or "").strip()
    if "\\" in text:
        dom, user = text.split("\\", 1)
        return dom, user
    return "", text
