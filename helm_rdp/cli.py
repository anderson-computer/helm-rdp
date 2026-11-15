"""Command-line options (no Qt): --version, --help and "connect to this host".

    helm-rdp [--host H] [--user U] [--port P] [--password-fd N] [file.rdp]

mstsc-style switches are accepted too: /v:host[:port] /f /w:N /h:N /admin
/multimon /edit file.rdp.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from . import APP_ID, APP_NAME, __version__

USAGE_EXAMPLES = """\
examples:
  helm-rdp                                  open the connection window
  helm-rdp --host pc01                      connect to pc01; ask for the user name and password
  helm-rdp --host 10.0.0.5 --user 'CORP\\mike' --port 3390
  helm-rdp work.rdp                         open an .rdp file and connect
  helm-rdp --edit work.rdp                  open an .rdp file for editing (like mstsc /edit)
  helm-rdp --host 10.0.0.5 --user mike --password-fd 3   (password on fd 3)
  helm-rdp /v:pc01:3390 /f                  mstsc-style switches also work
Missing user names and passwords are asked for in a window; nothing
secret is ever passed on the command line."""


def _translate_mstsc(args: List[str]) -> List[str]:
    out = []
    for a in args:
        low = a.lower()
        if low.startswith("/v:"):
            out += ["--host", a[3:]]
        elif low == "/f":
            out.append("--fullscreen")
        elif low.startswith("/w:"):
            out += ["--width", a[3:]]
        elif low.startswith("/h:"):
            out += ["--height", a[3:]]
        elif low in ("/admin", "/console"):
            out.append("--admin")
        elif low == "/multimon":
            out.append("--multimon")
        elif low == "/edit":
            out.append("--edit")
        elif low in ("/?", "/help"):
            out.append("--help")
        else:
            out.append(a)
    return out


def parse_cli(argv) -> Tuple[List[str], Dict]:
    """Returns (qt_argv, opts). Unknown options are passed through to Qt."""
    import argparse

    from .rdpfile import split_address

    parser = argparse.ArgumentParser(
        prog=APP_ID,
        usage="%(prog)s [--host HOST] [--user USER] [--port PORT] [--password-fd N] "
              "[--fullscreen] [--width W --height H] [--admin] [--edit] [file.rdp] [Qt options]",
        description=APP_NAME + " - Remote Desktop Connection (mstsc) style RDP client.",
        epilog=USAGE_EXAMPLES + "\n\nStandard Qt options (e.g. -platform offscreen) are passed through. "
        "Settings: ~/.config/" + APP_ID + "/, master configuration /etc/helm-rdp/helm-rdp.conf.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=APP_NAME + " " + __version__)
    parser.add_argument("--host", nargs="?", const="", default=None,
                        help="computer to connect to on start (also host:port)")
    parser.add_argument("--user", nargs="?", const="", default=None,
                        help="user name, DOMAIN\\user or user@domain (asked for if missing)")
    parser.add_argument("--port", nargs="?", const="", default=None, help="RDP port (default 3389)")
    parser.add_argument("--password-fd", metavar="N", type=int, default=None,
                        help="read the password from open file descriptor N (a pipe from the "
                             "program that started Helm); never put it in argv or env")
    parser.add_argument("--fullscreen", "-f", action="store_true", help="full screen")
    parser.add_argument("--width", type=int, default=None, help="desktop width in pixels")
    parser.add_argument("--height", type=int, default=None, help="desktop height in pixels")
    parser.add_argument("--admin", action="store_true", help="connect to the administrative session")
    parser.add_argument("--multimon", action="store_true", help="use all monitors")
    parser.add_argument("--edit", action="store_true", help="open the .rdp file without connecting")
    parser.add_argument("--no-connect", action="store_true", help="fill in the window but do not connect")
    opts, rest = parser.parse_known_args(_translate_mstsc(argv[1:]))
    files = [a for a in rest if a.lower().endswith(".rdp") and not a.startswith("-")]
    rest = [a for a in rest if a not in files]
    if len(files) > 1:
        parser.error("give one .rdp file")
    out: Dict = {"host": None, "port": None, "user": None, "password": None,
                 "file": os.path.abspath(files[0]) if files else None,
                 "fullscreen": opts.fullscreen, "width": opts.width, "height": opts.height,
                 "admin": opts.admin, "multimon": opts.multimon,
                 "connect": False, "edit": opts.edit}
    if out["file"] and not os.path.isfile(out["file"]):
        parser.error("file not found: %s" % files[0])
    if opts.host:
        host, port = split_address(opts.host)
        if not host:
            parser.error("--host: no computer name")
        out["host"] = host
        out["port"] = port
    elif opts.user or opts.port or opts.password_fd is not None:
        if not out["file"]:
            parser.error("--user, --port and --password-fd need --host (or an .rdp file)")
    if opts.port not in (None, ""):
        try:
            p = int(opts.port)
            if not 0 < p < 65536:
                raise ValueError
            out["port"] = p
        except ValueError:
            parser.error("--port: not a port number: %s" % opts.port)
    if opts.user:
        out["user"] = opts.user
    if opts.password_fd is not None:
        try:
            out["password"] = read_password_fd(opts.password_fd)
        except (OSError, ValueError) as exc:
            parser.error("--password-fd %s: %s" % (opts.password_fd, exc))
    out["connect"] = bool((out["host"] or out["file"]) and not opts.edit and not opts.no_connect)
    return [argv[0]] + rest, out


def read_password_fd(fd: int, limit: int = 65536) -> str:
    """Read a password from an inherited fd until EOF, then close it.
    One trailing newline is dropped. A terminal is refused (use the
    credentials window instead). Same as Skiff and Porthole."""
    if fd < 0 or fd in (1, 2):
        raise ValueError("invalid file descriptor (use 0 or a pipe on 3 or higher)")
    try:
        if os.isatty(fd):
            raise ValueError("is a terminal")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError("too much data")
            chunks.append(chunk)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    text = b"".join(chunks).decode("utf-8")
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    return text
