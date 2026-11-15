"""Run one FreeRDP session and work out how it ended. No Qt here.

The child gets the password through a pipe (FreeRDP 3: /args-from:fd:N,
FreeRDP 2: stdin with /from-stdin:force); the pipe is written once and
closed before the user sees the remote desktop. FreeRDP's log is read
line by line (through stdbuf so it is not block-buffered) to see when the
session is up and why it ended.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from typing import Callable, List, Optional

from .freerdp import ARGS_FD_PLACEHOLDER, LaunchPlan, _clean_env

# Seen once the session is drawing (post-connect): FreeRDP 2 and 3.
CONNECTED_RE = re.compile(r"com\.freerdp\.gdi\].*Local framebuffer format|"
                          r"Loading Dynamic Virtual Channel|xf_post_connect|gdi_init_ex")
ERRCONNECT_RE = re.compile(r"\b(ERRCONNECT_[A-Z_]+|ERRINFO_[A-Z_]+|STATUS_[A-Z_]+)\b")
CERT_RE = re.compile(r"automatically denying|CERTIFICATE NAME MISMATCH|fingerprint|"
                     r"Certificate verification failure|does not match", re.I)

AUTH_FAILURES = {"ERRCONNECT_LOGON_FAILURE", "ERRCONNECT_AUTHENTICATION_FAILED",
                 "ERRCONNECT_WRONG_PASSWORD", "STATUS_LOGON_FAILURE", "STATUS_WRONG_PASSWORD",
                 "ERRINFO_LOGON_FAILED_OTHER", "ERRCONNECT_NO_OR_MISSING_CREDENTIALS",
                 "STATUS_NO_SUCH_USER"}

# FreeRDP client exit codes (client/X11 in 2.x, client/common in 3.x).
EXIT_TEXT = {
    0: None, 1: None, 2: None, 11: None, 12: None,
    3: "The remote session was disconnected because there were no keyboard or mouse "
       "inputs for a long time (idle time-out).",
    4: "The remote session ended because the total logon time limit was reached.",
    5: "The remote session was disconnected because another user connected to the session.",
    6: "The remote computer ran out of memory.",
    7: "The remote computer denied the connection.",
    9: "The connection was denied because the user account is not authorized for remote login.",
    10: "The remote computer requires fresh credentials.",
}


class Outcome:
    """How a session ended: kind is one of
    ok, auth, cert, dns, connect, password_expired, account, tls, cancelled, error."""

    def __init__(self, kind: str, message: str = "", code: int = 0, errors: Optional[List[str]] = None):
        self.kind = kind
        self.message = message
        self.code = code
        self.errors = errors or []

    def __repr__(self) -> str:
        return "Outcome(%r, code=%d, errors=%r)" % (self.kind, self.code, self.errors)


NOT_FOUND_TEXT = ("Remote Desktop can't find the computer \"{host}\". This might mean that "
                  "\"{host}\" does not belong to the specified network. Verify the computer "
                  "name and domain that you are trying to connect to.")
CANT_CONNECT_TEXT = ("Remote Desktop can't connect to the remote computer for one of these reasons:\n\n"
                     "1) Remote access to the server is not enabled\n"
                     "2) The remote computer is turned off\n"
                     "3) The remote computer is not available on the network\n\n"
                     "Make sure the remote computer is turned on and connected to the network, "
                     "and that remote access is enabled.")


def classify(code: int, lines: List[str], host: str, connected: bool) -> Outcome:
    text = "\n".join(lines[-400:])
    errors: List[str] = []
    for m in ERRCONNECT_RE.finditer(text):
        if m.group(1) not in errors:
            errors.append(m.group(1))
    es = set(errors)
    if es & AUTH_FAILURES or code in (132, 134, 154):
        return Outcome("auth", "The logon attempt failed.", code, errors)
    if es & {"ERRCONNECT_PASSWORD_EXPIRED", "ERRCONNECT_PASSWORD_MUST_CHANGE",
             "ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED", "STATUS_PASSWORD_EXPIRED",
             "STATUS_PASSWORD_MUST_CHANGE"} or code in (148, 149):
        return Outcome("password_expired", "You must change your password before logging on. "
                       "Change it on the remote computer's domain, then try again.", code, errors)
    if es & {"ERRCONNECT_ACCOUNT_LOCKED_OUT", "ERRCONNECT_ACCOUNT_DISABLED",
             "ERRCONNECT_ACCOUNT_RESTRICTION", "ERRCONNECT_ACCOUNT_EXPIRED",
             "STATUS_ACCOUNT_LOCKED_OUT", "STATUS_ACCOUNT_DISABLED"} or code in (135, 151):
        return Outcome("account", "Your account is locked out, disabled, expired or restricted "
                       "on the remote computer. Contact your administrator.", code, errors)
    if es & {"ERRCONNECT_DNS_NAME_NOT_FOUND", "ERRCONNECT_DNS_ERROR"} or code in (139, 140):
        return Outcome("dns", NOT_FOUND_TEXT.format(host=host), code, errors)
    if CERT_RE.search(text) and not connected and code != 0:
        return Outcome("cert", "The remote computer presented a different certificate than the one "
                       "that was checked a moment ago, so the connection was stopped. Try again; "
                       "if this keeps happening someone may be intercepting the connection.",
                       code, errors)
    if not connected and (es & {"ERRCONNECT_CONNECT_TRANSPORT_FAILED", "ERRCONNECT_CONNECT_FAILED",
                                "ERRCONNECT_CONNECT_UNDEFINED"} or code in (131, 141, 147)):
        return Outcome("connect", CANT_CONNECT_TEXT, code, errors)
    if not connected and (es & {"ERRCONNECT_TLS_CONNECT_FAILED", "ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED"}
                          or code in (133, 143)):
        return Outcome("tls", "An authentication error has occurred. The security negotiation "
                       "with the remote computer failed. Check the Advanced tab settings "
                       "(Network Level Authentication) or ask your administrator.", code, errors)
    if code == -signal.SIGTERM or (not connected and "ERRCONNECT_CONNECT_CANCELLED" in es):
        return Outcome("cancelled", "", code, errors)
    if code in EXIT_TEXT and EXIT_TEXT[code]:
        return Outcome("error", EXIT_TEXT[code], code, errors)
    if code in EXIT_TEXT or (connected and 0 <= code < 128):
        return Outcome("ok", "", code, errors)
    if code == 128:
        return Outcome("error", "FreeRDP did not accept the connection settings. See the session log.", code, errors)
    return Outcome("error", "The connection ended unexpectedly (FreeRDP exit code %d%s)." % (
        code, (": " + ", ".join(errors)) if errors else ""), code, errors)


class Session:
    """One FreeRDP child process. Callbacks run on a reader thread."""

    def __init__(self, plan: LaunchPlan, on_line: Optional[Callable[[str], None]] = None,
                 on_connected: Optional[Callable[[], None]] = None,
                 on_finished: Optional[Callable[[int, List[str], bool], None]] = None):
        self.plan = plan
        self.on_line = on_line
        self.on_connected = on_connected
        self.on_finished = on_finished
        self.proc: Optional[subprocess.Popen] = None
        self.lines: List[str] = []
        self.connected = False
        self.started_at = 0.0
        self._cancelled = False

    @property
    def pid(self) -> Optional[int]:
        return self.proc.pid if self.proc else None

    def start(self) -> None:
        argv = list(self.plan.argv)
        pass_fds = ()
        rfd = wfd = None
        if self.plan.args_fd_data is not None:
            rfd, wfd = os.pipe()
            if len(self.plan.args_fd_data) > 60000:
                raise ValueError("Connection settings are too long.")
            os.write(wfd, self.plan.args_fd_data)  # fits in the pipe buffer
            os.close(wfd)
            argv = [a.replace(ARGS_FD_PLACEHOLDER, str(rfd)) for a in argv]
            pass_fds = (rfd,)
        stdbuf = shutil.which("stdbuf")
        if stdbuf:
            argv = [stdbuf, "-oL", "-eL"] + argv
        try:
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE if self.plan.stdin_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, pass_fds=pass_fds,
                env=_clean_env(), close_fds=True)
        finally:
            if rfd is not None:
                os.close(rfd)
        self.started_at = time.time()
        if self.plan.stdin_data is not None:
            try:
                self.proc.stdin.write(self.plan.stdin_data)
                self.proc.stdin.flush()
            except OSError:
                pass
            finally:
                try:
                    self.proc.stdin.close()
                except OSError:
                    pass
        threading.Thread(target=self._read, name="freerdp-reader", daemon=True).start()

    def _read(self) -> None:
        assert self.proc is not None
        for raw in iter(self.proc.stdout.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if "com.freerdp.utils" in line and ("backtrace" in line or re.search(r"\] - \d+: ", line)):
                continue  # FreeRDP 2 prints a stack trace on SIGTERM
            if not line.strip():
                continue
            self.lines.append(line)
            if len(self.lines) > 5000:
                del self.lines[:1000]
            if self.on_line:
                self.on_line(line)
            if not self.connected and CONNECTED_RE.search(line):
                self.connected = True
                if self.on_connected:
                    self.on_connected()
        code = self.proc.wait()
        try:
            self.proc.stdout.close()
        except OSError:
            pass
        if self._cancelled:
            code = -signal.SIGTERM  # Helm stopped it (Cancel / Disconnect)
        if self.on_finished:
            self.on_finished(code, self.lines, self.connected)

    def terminate(self) -> None:
        if self.proc and self.proc.poll() is None:
            self._cancelled = True
            try:
                self.proc.terminate()
            except OSError:
                pass

    def running(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)
