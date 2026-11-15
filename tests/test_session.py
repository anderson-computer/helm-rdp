"""Session: a fake FreeRDP gets the password only through the pipe."""

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from tests.helpers import temp_config

from helm_rdp import freerdp, session
from helm_rdp.rdpfile import RdpProfile

SECRET = "pipe-only-%d" % os.getpid()

FAKE = r'''#!%s
import os, sys
from pathlib import Path
out = os.environ["FAKE_OUT"]
args = sys.argv[1:]
data = ""
if args and args[0].startswith("/args-from:fd:"):
    fd = int(args[0].split(":")[2]); data = os.read(fd, 65536).decode()
else:
    sys.stdout.write("Password: "); sys.stdout.flush(); data = sys.stdin.readline()
cmd = Path("/proc/self/cmdline").read_bytes().decode(errors="replace")
env = Path("/proc/self/environ").read_bytes().decode(errors="replace")
open(out, "w").write("PIPE=" + data.replace("\n", "|") + "\nCMD=" + cmd + "\nENV=" + env)
print("[INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32", flush=True)
code = int(os.environ.get("FAKE_CODE", "0"))
if code == 134:
    print("[ERROR][com.freerdp.core] - ERRCONNECT_LOGON_FAILURE [0x00020014]")
sys.exit(code)
''' % sys.executable


class SessionTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_config()
        self.fake = os.path.join(self.dir, "xfreerdp")
        Path(self.fake).write_text(FAKE)
        os.chmod(self.fake, 0o755)
        self.out = os.path.join(self.dir, "out.txt")
        os.environ["FAKE_OUT"] = self.out

    def run_session(self, major, code=0):
        os.environ["FAKE_CODE"] = str(code)
        p = RdpProfile()
        p.set_address("127.0.0.1:3390")
        plan = freerdp.plan(freerdp.FreeRdp(self.fake, major), p, freerdp.Credentials("mike", SECRET))
        done = threading.Event()
        res = {}

        def fin(c, lines, conn):
            res.update(code=c, lines=list(lines), connected=conn)
            done.set()
        s = session.Session(plan, on_connected=lambda: res.setdefault("up", True), on_finished=fin)
        s.start()
        self.assertTrue(done.wait(20))
        return res, Path(self.out).read_text()

    def check_secret_only_in_pipe(self, text):
        pipe, rest = text.split("\nCMD=", 1)
        self.assertIn(SECRET, pipe)
        self.assertNotIn(SECRET, rest, "password leaked to argv or environment")

    def test_v3_args_fd(self):
        res, text = self.run_session(3)
        self.assertTrue(res.get("up"))
        self.assertTrue(res["connected"])
        self.assertIn("/p:" + SECRET, text)
        self.check_secret_only_in_pipe(text)
        self.assertEqual(session.classify(res["code"], res["lines"], "h", True).kind, "ok")

    def test_v2_stdin(self):
        res, text = self.run_session(2)
        self.assertTrue(res["connected"])
        self.assertIn("PIPE=" + SECRET + "|", text)
        self.check_secret_only_in_pipe(text)

    def test_logon_failure(self):
        res, _ = self.run_session(3, code=134)
        self.assertEqual(session.classify(res["code"], res["lines"], "h", res["connected"]).kind, "auth")


class ClassifyTest(unittest.TestCase):
    def k(self, code, lines, connected=False):
        return session.classify(code, lines, "pc01", connected).kind

    def test_kinds(self):
        self.assertEqual(self.k(131, ["ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D]"]), "connect")
        self.assertEqual(self.k(140, ["ERRCONNECT_DNS_NAME_NOT_FOUND"]), "dns")
        self.assertEqual(self.k(143, ["No certificate stored, automatically denying."]), "cert")
        self.assertEqual(self.k(132, ["ERRCONNECT_AUTHENTICATION_FAILED"]), "auth")
        self.assertEqual(self.k(148, ["ERRCONNECT_PASSWORD_EXPIRED"]), "password_expired")
        self.assertEqual(self.k(135, ["ERRCONNECT_ACCOUNT_LOCKED_OUT"]), "account")
        self.assertEqual(self.k(133, ["ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED"]), "tls")
        self.assertEqual(self.k(0, [], True), "ok")
        self.assertEqual(self.k(12, [], True), "ok")
        self.assertEqual(self.k(3, [], True), "error")
        self.assertEqual(self.k(-15, []), "cancelled")
        self.assertIn("can't find the computer \"pc01\"",
                      session.classify(140, ["ERRCONNECT_DNS_NAME_NOT_FOUND"], "pc01", False).message)


if __name__ == "__main__":
    unittest.main()
