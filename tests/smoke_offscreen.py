"""Headless GUI smoke test (QT_QPA_PLATFORM=offscreen).

Builds the main window, the five option tabs and every dialog, checks the
widgets exist and that profile <-> UI round-trips, and (with SHOT_DIR set)
saves screenshots. HELM_ROOT points at an installed copy (/opt/helm-rdp).
"""

import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.environ.get("HELM_ROOT") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.abspath(ROOT))
tmp = tempfile.mkdtemp(prefix="helm-smoke-")
os.environ["XDG_CONFIG_HOME"] = tmp
os.environ["HELM_RDP_CONF"] = os.path.join(tmp, "none.conf")

from helm_rdp.qtcompat import QApplication, QT_VERSION, QT_VERSION_STR  # noqa: E402

app = QApplication(sys.argv[:1])
app.setStyle("Fusion")
from helm_rdp import certcheck, rdpfile  # noqa: E402
from helm_rdp.about_config import LOGO_FILE  # noqa: E402
from helm_rdp.qtcompat import QIcon  # noqa: E402

app.setWindowIcon(QIcon(LOGO_FILE))
from helm_rdp.dialogs import (AudioDialog, CertificateDialog, CredentialsDialog,  # noqa: E402
                              DevicesDialog, GatewayDialog, KnownCertsDialog)
from helm_rdp.help_dialogs import AboutDialog, HelpDialog  # noqa: E402
from helm_rdp.main_window import MainWindow  # noqa: E402

SHOTS = os.environ.get("SHOT_DIR")
fails = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails.append(what)


def shot(widget, name):
    widget.show()
    app.processEvents()
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        widget.grab().save(os.path.join(SHOTS, name + ".png"))


print("Qt %s (PyQt%d)" % (QT_VERSION_STR, QT_VERSION))
settings = {"recent": [{"host": "ws-eng-07.corp.example.com", "username": "CORP\\mike"},
                       {"host": "198.51.100.20:3390", "username": "administrator"},
                       {"host": "build01", "username": "mike"}],
            "password_backend": "auto", "vault_file": "", "show_options": False, "last_tab": 0}
w = MainWindow(cli={}, settings=settings)
w._no_minimize = True
w.computer.setEditText("ws-eng-07.corp.example.com")
w.username.setEditText("CORP\\mike")
w.set_options_visible(False)
shot(w, "main-compact")
check(w.compact.isVisible() and not w.tabs_holder.isVisible(), "compact view")
check(w.computer.count() == 3, "recent computers in the drop-down")
w.set_options_visible(True)
check(w.tabs.count() == 5, "five option tabs")
names = [w.tabs.tabText(i) for i in range(w.tabs.count())]
check(names == ["General", "Display", "Local Resources", "Experience", "Advanced"], "tab names %s" % names)
for i, n in enumerate(["general", "display", "local-resources", "experience", "advanced"]):
    w.tabs.setCurrentIndex(i)
    shot(w, "tab-" + n)

# profile <-> UI
p = w.profile_from_ui()
check(p.get_str("full address") == "ws-eng-07.corp.example.com", "full address from UI")
check(p.get_str("username") == "CORP\\mike", "username from UI")
w.size_slider.setValue(2)
p = w.profile_from_ui()
check(p.get_int("screen mode id") == 1 and (p.get_int("desktopwidth"), p.get_int("desktopheight")) == w.sizes[2],
      "windowed size from slider")
w.speed.setCurrentIndex(0)
w._speed_changed()
p = w.profile_from_ui()
check(p.get_int("connection type") == 1 and p.get_int("disable wallpaper") == 1
      and p.get_int("bitmapcachepersistenable") == 1, "modem preset")
f = os.path.join(tmp, "t.rdp")
w._save_to(f)
q = rdpfile.load_rdp(f)
check(q.get_int("connection type") == 1 and q.get_str("full address") == "ws-eng-07.corp.example.com",
      "Save As .rdp round-trip")
check(open(f, "rb").read(2) == b"\xff\xfe", ".rdp saved as UTF-16 LE with BOM")
w.open_file(f)
check(w.windowTitle().endswith("t.rdp"), "title shows open file")

# dialogs
info = certcheck.CertInfo("ws-eng-07.corp.example.com", 3389)
info.protocol = certcheck.PROTOCOL_HYBRID
info.der = b"0" * 64
info.subject, info.issuer, info.names = "CN=WS-ENG-07", "CN=WS-ENG-07", ["WS-ENG-07"]
info.not_before, info.not_after, info.self_signed = "2026-01-02 09:00 EST", "2026-07-03 09:00 EDT", True
info.trust_error = "self-signed certificate"
cd = CertificateDialog(w, info)
shot(cd, "certificate")
check(cd.yes_btn.text() == "Yes" and cd.no_btn.isDefault(), "certificate dialog: No is the default")
cd2 = CertificateDialog(w, info, changed=True, old_fp="ab:" * 31 + "cd")
shot(cd2, "certificate-changed")
cr = CredentialsDialog(w, "ws-eng-07.corp.example.com", "CORP\\mike", remember_label="system keychain")
shot(cr, "credentials")
cr2 = CredentialsDialog(w, "build01", "mike", message="The logon attempt failed.", remember_label="encrypted vault")
shot(cr2, "credentials-failed")
check(cr.remember.text() == "Remember me (system keychain)", "Remember me shows the store")
shot(AudioDialog(w, 0, False), "audio")
shot(DevicesDialog(w, False, [os.path.expanduser("~")]), "devices")
gd = GatewayDialog(w, rdpfile.RdpProfile())
shot(gd, "gateway")
shot(KnownCertsDialog(w, os.path.join(tmp, "kc.json")), "known-certs")
ab = AboutDialog(w)
shot(ab, "about")
check("Helm" in ab.name.text() and ab.version.text().startswith("Version "), "About dialog")
hd = HelpDialog(w)
shot(hd, "help")
check("Credentials and saved passwords" in hd.browser.toPlainText(), "Help topics")

# --- connect flow with a fake FreeRDP: wrong password -> re-prompt -> success
import time  # noqa: E402
from helm_rdp import config as hconfig  # noqa: E402
from helm_rdp.qtcompat import QMessageBox, QTimer  # noqa: E402

fake = os.path.join(tmp, "fake-xfreerdp")
with open(fake, "w") as fh:
    fh.write("""#!%s
import os, sys
data = os.read(int(sys.argv[1].split(":")[2]), 65536).decode() if sys.argv[1].startswith("/args-from:fd:") else sys.stdin.readline()
if "/p:right" in data or data.strip() == "right":
    print("[INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32", flush=True)
    sys.exit(0)
print("[ERROR][com.freerdp.core] - ERRCONNECT_LOGON_FAILURE [0x00020014]", flush=True)
sys.exit(134)
""" % sys.executable)
os.chmod(fake, 0o755)
with open(os.environ["HELM_RDP_CONF"], "w") as fh:
    fh.write("[helm-rdp]\nfreerdp = %s\n" % fake)
w.master = hconfig.load_master()
w.open_file(f)
w.auth_level.setCurrentIndex(w.auth_level.findData(0))   # Connect and don't warn me: no cert check
w.computer.setEditText("fake-pc:3390")
w.username.setEditText("mike")
prompts, boxes = [], []


def answer():
    m = app.activeModalWidget()
    if isinstance(m, CredentialsDialog):
        prompts.append(m.message.text() if m.message.isVisible() else "")
        if len(prompts) == 2:
            shot(m, "credentials-retry")
        m.password.setText("wrong" if len(prompts) == 1 else "right")
        m.ok_button.click()
    elif isinstance(m, QMessageBox):
        boxes.append(m.text())
        shot(m, "error-%d" % len(boxes))
        m.close()


t = QTimer()
t.timeout.connect(answer)
t.start(100)
att = w.connect_clicked()
t0 = time.time()
while time.time() - t0 < 20 and getattr(getattr(att, "outcome", None), "kind", "auth") == "auth":
    app.processEvents()
    time.sleep(0.02)
check(len(prompts) == 2 and "logon attempt failed" in prompts[1], "wrong password re-prompts: %s" % prompts)
check(att.connected and att.outcome.kind == "ok", "fake session connected and ended ok (%r)" % getattr(att, "outcome", None))
check(hconfig.recent_username(w.settings, "fake-pc:3390") == "mike", "connected computer added to recent list")

# --- unreachable computer -> mstsc "can't connect" message
w.auth_level.setCurrentIndex(w.auth_level.findData(2))
import socket  # noqa: E402
so = socket.socket()
so.bind(("127.0.0.1", 0))
free_port = so.getsockname()[1]
so.close()
w.computer.setEditText("127.0.0.1:%d" % free_port)
att2 = w.connect_clicked()
t0 = time.time()
while time.time() - t0 < 15 and not boxes:
    app.processEvents()
    time.sleep(0.02)
check(boxes and "can't connect to the remote computer" in boxes[0], "unreachable computer: %s" % (boxes[:1],))
t.stop()
w.set_options_visible(False)
w.tabs.setCurrentIndex(0)
print("smoke: %s" % ("PASS" if not fails else "FAIL %s" % fails))
sys.exit(1 if fails else 0)
