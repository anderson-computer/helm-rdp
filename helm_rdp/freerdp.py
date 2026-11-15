"""Turn an RdpProfile into a FreeRDP command line, and find FreeRDP.

Rocky Linux 9 ships FreeRDP 2.11 (xfreerdp, AppStream); Rocky Linux 10
ships FreeRDP 3 (xfreerdp, AppStream). Both are supported.

Secrets never go on the command line or into the environment:

  FreeRDP 3  every option, password included, is written to a pipe and
             FreeRDP reads it with /args-from:fd:N (argv holds only that).
  FreeRDP 2  options go in argv without the password; /from-stdin:force
             makes FreeRDP read the password from its stdin, which is a
             pipe Helm writes once and closes.

No Qt here, so it is unit tested headless.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from .rdpfile import RdpProfile, split_user

# Preferred order. sdl-freerdp3 / xfreerdp3 are the names some builds use.
CANDIDATES = ["xfreerdp3", "xfreerdp", "sdl-freerdp3", "sdl-freerdp", "wlfreerdp3", "wlfreerdp"]

NETWORK = {1: "modem", 2: "broadband-low", 3: "broadband-high", 4: "broadband-high",
           5: "wan", 6: "lan", 7: "auto"}


class FreeRdpNotFound(Exception):
    pass


class FreeRdp:
    def __init__(self, path: str, major: int, version: str = ""):
        self.path = path
        self.major = major
        self.version = version

    def __repr__(self) -> str:
        return "FreeRdp(%r, %d, %r)" % (self.path, self.major, self.version)


def find_freerdp(setting: str = "auto") -> FreeRdp:
    setting = (setting or "auto").strip()
    paths = []
    if setting and setting != "auto":
        p = shutil.which(setting) or (setting if os.path.isfile(setting) else None)
        if not p:
            raise FreeRdpNotFound("The FreeRDP client set in helm-rdp.conf was not found: %s" % setting)
        paths = [p]
    else:
        for name in CANDIDATES:
            p = shutil.which(name)
            if p:
                paths.append(p)
    if not paths:
        raise FreeRdpNotFound(
            "FreeRDP is not installed. Install it with:\n\n    sudo dnf install freerdp")
    path = paths[0]
    version, major = probe_version(path)
    return FreeRdp(path, major, version)


def probe_version(path: str) -> Tuple[str, int]:
    try:
        out = subprocess.run([path, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=10, check=False,
                             env=_clean_env()).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        out = ""
    m = re.search(r"version\s+(\d+)\.(\d+)\.(\d+)", out)
    if m:
        return "%s.%s.%s" % m.groups(), int(m.group(1))
    return "", 3 if path.endswith("3") else 2


def _clean_env() -> Dict[str, str]:
    env = dict(os.environ)
    for k in list(env):
        if k.upper() in ("FREERDP_PASSWORD", "PASSWORD", "RDP_PASSWORD") or k.startswith("HELM_SECRET"):
            env.pop(k, None)
    return env


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
class Credentials:
    def __init__(self, username: str = "", password: Optional[str] = None,
                 gateway_username: str = "", gateway_password: Optional[str] = None):
        self.username = username
        self.password = password
        self.gateway_username = gateway_username
        self.gateway_password = gateway_password

    def __repr__(self) -> str:  # never show secrets
        return "Credentials(%r, password=%s)" % (self.username, "***" if self.password else None)


def _onoff(flag: bool) -> str:
    return "+" if flag else "-"


def build_options(profile: RdpProfile, creds: Credentials, major: int,
                  cert_fingerprint: str = "", cert_policy: str = "deny",
                  title: str = "", log_level: str = "INFO", extra: str = "",
                  multimon_ok: bool = True) -> Tuple[List[str], List[str]]:
    """Return (public, secret) option lists.

    public: options that are safe to show (no passwords).
    secret: options carrying passwords, only for FreeRDP 3's /args-from
            pipe. For FreeRDP 2 it is empty and the password goes on stdin.
    cert_policy: "deny" (pin cert_fingerprint, refuse anything else) or
                 "ignore" ("Connect and don't warn me").
    """
    v3 = major >= 3
    o: List[str] = []
    secret: List[str] = []
    host, port = profile.address
    if not host:
        raise ValueError("No computer name")
    o.append("/v:%s" % host)
    if port and int(port) != 3389:
        o.append("/port:%d" % int(port))

    domain, user = split_user(creds.username or profile.get_str("username"))
    if profile.get_str("domain") and not domain:
        domain = profile.get_str("domain")
    if user:
        o.append("/u:%s" % user)
    if domain:
        o.append("/d:%s" % domain)
    if creds.password is not None:
        if v3:
            secret.append("/p:%s" % creds.password)
        else:
            o.append("/from-stdin:force")

    # --- certificate --------------------------------------------------------
    if cert_policy == "ignore":
        o.append("/cert:ignore")
    elif cert_fingerprint:
        o.append("/cert:deny,fingerprint:sha256:%s" % cert_fingerprint)
    else:
        o.append("/cert:deny")

    # --- security -------------------------------------------------------------
    if profile.get("enablecredsspsupport") is not None and not profile.get_bool("enablecredsspsupport", True):
        o.append("/sec:nla:off" if v3 else "-sec-nla")
    if profile.get_bool("administrative session"):
        o.append("/admin")
    lbi = profile.get_str("loadbalanceinfo")
    if lbi:
        o.append("/load-balance-info:%s" % lbi)

    # --- display ---------------------------------------------------------------
    fullscreen = profile.get_int("screen mode id", 2) == 2
    if fullscreen:
        o.append("/f")
        if profile.get_bool("use multimon") and multimon_ok:
            o.append("/multimon")
            mons = profile.get_str("selectedmonitors").strip()
            if mons:
                o.append("/monitors:%s" % mons)
    else:
        w, h = profile.get_int("desktopwidth", 1920), profile.get_int("desktopheight", 1080)
        o.append("/size:%dx%d" % (max(200, w), max(200, h)))
    if profile.get_bool("dynamic resolution"):
        o.append("/dynamic-resolution")
    if profile.get_bool("smart sizing"):
        o.append("/smart-sizing")
    bpp = profile.get_int("session bpp", 32)
    if bpp in (8, 15, 16, 24, 32):
        o.append("/bpp:%d" % bpp)
    if profile.get_bool("displayconnectionbar", True):
        o.append("/floatbar:sticky:off,default:visible,show:fullscreen")
    o.append("/t:%s" % (title or host))
    o.append("/wm-class:helm-rdp-session")

    # --- local resources ---------------------------------------------------------
    audiomode = profile.get_int("audiomode", 0)
    if audiomode == 0:
        o.append("/sound")
    elif audiomode == 1:
        o.append("/audio-mode:1")
    else:
        o.append("/audio-mode:2")
    if profile.get_bool("audiocapturemode"):
        o.append("/microphone")
    o.append("%sclipboard" % _onoff(profile.get_bool("redirectclipboard", True)))
    if profile.get_bool("redirectprinters"):
        o.append("/printer")
    if profile.get_bool("redirectsmartcards"):
        o.append("/smartcard")
    for d in profile.drives():
        if d == "*":
            o.append("/drives")
        elif d.lower() == "dynamicdrives":
            o.append("/drive:hotplug,*")
        else:
            path = os.path.expanduser(d)
            name = _share_name(path)
            o.append("/drive:%s,%s" % (name, path))
    if profile.get_int("keyboardhook", 2) == 0:
        o.append("-grab-keyboard")

    # --- experience -----------------------------------------------------------------
    ctype = profile.get_int("connection type", 7)
    o.append("/network:%s" % NETWORK.get(ctype, "auto"))
    bg, fonts, aero, drag, anims, themes, bmpcache = profile.experience()
    o += ["%swallpaper" % _onoff(bg), "%sfonts" % _onoff(fonts), "%saero" % _onoff(aero),
          "%swindow-drag" % _onoff(drag), "%smenu-anims" % _onoff(anims), "%sthemes" % _onoff(themes)]
    if v3:
        o.append("/cache:bitmap:%s" % ("on" if bmpcache else "off"))
    else:
        o.append("%sbitmap-cache" % _onoff(bmpcache))
    o.append("%scompression" % _onoff(profile.get_bool("compression", True)))
    if profile.get_bool("autoreconnection enabled", True):
        o.append("+auto-reconnect")
        retries = profile.get_int("autoreconnect max retries", 0)
        if retries > 0:
            o.append("/auto-reconnect-max-retries:%d" % retries)
    else:
        o.append("-auto-reconnect")

    # --- programs ---------------------------------------------------------------------
    shell = profile.get_str("alternate shell")
    if shell and not profile.get_bool("remoteapplicationmode"):
        o.append("/shell:%s" % shell)
        wd = profile.get_str("shell working directory")
        if wd:
            o.append("/shell-dir:%s" % wd)
    app = profile.get_str("remoteapplicationprogram")
    if profile.get_bool("remoteapplicationmode") and app:
        o.append("/app:program:%s" % app if v3 else "/app:%s" % app)

    # --- RD Gateway ---------------------------------------------------------------------
    gw = profile.get_str("gatewayhostname").strip()
    usage = profile.get_int("gatewayusagemethod", 4)
    if gw and usage in (1, 2) and profile.get_int("gatewayprofileusagemethod", 0) == 1:
        method = "direct" if usage == 1 else "detect"
        same = profile.get_bool("promptcredentialonce")
        g_user = creds.username if same else (creds.gateway_username or creds.username)
        g_dom, g_name = split_user(g_user)
        g_pass = creds.password if same else creds.gateway_password
        if v3:
            parts = ["g:%s" % gw, "usage-method:%s" % method]
            if g_name:
                parts.append("u:%s" % g_name)
            if g_dom:
                parts.append("d:%s" % g_dom)
            if g_pass is not None:
                secret.append("/gateway:%s,p:%s" % (",".join(parts), g_pass))
            else:
                o.append("/gateway:%s" % ",".join(parts))
        else:
            o += ["/g:%s" % gw, "/gateway-usage-method:%s" % method]
            if g_name:
                o.append("/gu:%s" % (("%s\\%s" % (g_dom, g_name)) if g_dom else g_name))
            # FreeRDP 2 asks for the gateway password on stdin after the
            # main password (see stdin_payload).

    o.append("/log-level:%s" % (log_level or "INFO"))
    if extra:
        try:
            o += [a for a in shlex.split(extra) if not re.match(r"^[/+-](p|gp|from-stdin|args-from)(:|$)", a)]
        except ValueError:
            pass
    return o, secret


def _share_name(path: str) -> str:
    base = os.path.basename(os.path.normpath(path)) or "root"
    if os.path.normpath(path) == os.path.normpath(os.path.expanduser("~")):
        base = "home"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", base)[:32] or "share"


class LaunchPlan:
    """Everything needed to start one session."""

    def __init__(self, argv: List[str], stdin_data: Optional[bytes], args_fd_data: Optional[bytes]):
        self.argv = argv                  # never contains a password
        self.stdin_data = stdin_data      # FreeRDP 2 password line(s)
        self.args_fd_data = args_fd_data  # FreeRDP 3 /args-from payload

    def __repr__(self) -> str:
        return "LaunchPlan(argv=%r, stdin=%s, args_fd=%s)" % (
            self.argv, "<%d bytes>" % len(self.stdin_data) if self.stdin_data else None,
            "<%d bytes>" % len(self.args_fd_data) if self.args_fd_data else None)


ARGS_FD_PLACEHOLDER = "{fd}"


def plan(client: FreeRdp, profile: RdpProfile, creds: Credentials, **kw) -> LaunchPlan:
    public, secret = build_options(profile, creds, client.major, **kw)
    for a in public + secret:
        if "\n" in a or "\r" in a:
            raise ValueError("Line breaks are not allowed in connection settings or passwords.")
    if client.major >= 3:
        payload = "\n".join(public + secret) + "\n"
        return LaunchPlan([client.path, "/args-from:fd:" + ARGS_FD_PLACEHOLDER], None, payload.encode("utf-8"))
    stdin = None
    if creds.password is not None:
        lines = [creds.password]
        gw = profile.get_str("gatewayhostname").strip()
        if gw and profile.get_int("gatewayusagemethod", 4) in (1, 2) and profile.get_int("gatewayprofileusagemethod", 0) == 1:
            same = profile.get_bool("promptcredentialonce")
            gp = creds.password if same else creds.gateway_password
            if gp is not None:
                lines.append(gp)
        stdin = ("\n".join(lines) + "\n").encode("utf-8")
    return LaunchPlan([client.path] + public, stdin, None)


def display_command(p: LaunchPlan) -> str:
    """The command as shown in the session log (no secrets by construction)."""
    if p.args_fd_data is not None:
        shown = [a for a in p.args_fd_data.decode("utf-8").splitlines()
                 if not re.match(r"^/p:", a)]
        shown = [re.sub(r",p:.*$", ",p:********", a) if a.startswith("/gateway:") else a for a in shown]
        has_pw = any(a.startswith("/p:") for a in p.args_fd_data.decode("utf-8").splitlines())
        return "%s /args-from:fd  (pipe: %s%s)" % (p.argv[0], " ".join(shlex.quote(a) for a in shown),
                                                 " /p:********" if has_pw else "")
    return " ".join(shlex.quote(a) for a in p.argv) + ("  (password on stdin)" if p.stdin_data else "")
