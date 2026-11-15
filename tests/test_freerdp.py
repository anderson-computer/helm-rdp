import os
import stat
import tempfile
import unittest

from tests.helpers import temp_config

from helm_rdp import freerdp
from helm_rdp.rdpfile import RdpProfile

SECRET = "S3cr3t pass;$(id)"


def prof(**kw):
    p = RdpProfile()
    p.set_address(kw.pop("address", "pc01.example.com:3390"))
    for k, v in kw.items():
        p.set(k.replace("_", " "), v)
    return p


class BuildTest(unittest.TestCase):
    def setUp(self):
        temp_config()

    def test_v3_password_only_in_args_fd(self):
        c = freerdp.FreeRdp("/usr/bin/xfreerdp", 3, "3.10.3")
        plan = freerdp.plan(c, prof(), freerdp.Credentials("CORP\\mike", SECRET), cert_fingerprint="aa:bb")
        self.assertEqual(plan.argv, ["/usr/bin/xfreerdp", "/args-from:fd:{fd}"])
        lines = plan.args_fd_data.decode().splitlines()
        self.assertIn("/v:pc01.example.com", lines)
        self.assertIn("/port:3390", lines)
        self.assertIn("/u:mike", lines)
        self.assertIn("/d:CORP", lines)
        self.assertIn("/p:" + SECRET, lines)
        self.assertIn("/cert:deny,fingerprint:sha256:aa:bb", lines)
        self.assertIsNone(plan.stdin_data)
        self.assertNotIn(SECRET, freerdp.display_command(plan))
        self.assertNotIn(SECRET, repr(plan))

    def test_v2_password_only_on_stdin(self):
        c = freerdp.FreeRdp("/usr/bin/xfreerdp", 2, "2.11.7")
        plan = freerdp.plan(c, prof(), freerdp.Credentials("mike", SECRET))
        self.assertTrue(all(SECRET not in a for a in plan.argv))
        self.assertIn("/from-stdin:force", plan.argv)
        self.assertEqual(plan.stdin_data, (SECRET + "\n").encode())
        self.assertIn("/cert:deny", plan.argv)
        self.assertIn("+bitmap-cache", plan.argv)
        self.assertNotIn(SECRET, freerdp.display_command(plan))

    def test_display_settings(self):
        pub, _ = freerdp.build_options(prof(screen_mode_id=1, desktopwidth=1280, desktopheight=800,
                                            session_bpp=16), freerdp.Credentials("u", None), 3)
        self.assertIn("/size:1280x800", pub)
        self.assertIn("/bpp:16", pub)
        self.assertNotIn("/f", pub)
        pub, _ = freerdp.build_options(prof(screen_mode_id=2, use_multimon=1, selectedmonitors="0,1"),
                                       freerdp.Credentials("u", None), 3)
        self.assertIn("/f", pub)
        self.assertIn("/multimon", pub)
        self.assertIn("/monitors:0,1", pub)

    def test_local_resources_and_experience(self):
        p = prof(audiomode=2, audiocapturemode=1, redirectclipboard=0, redirectprinters=1,
                 redirectsmartcards=1, keyboardhook=0)
        p.set_drives(["*", "DynamicDrives", "/home/mike"])
        p.apply_connection_type(1)
        pub, _ = freerdp.build_options(p, freerdp.Credentials("u", None), 3)
        for a in ("/audio-mode:2", "/microphone", "-clipboard", "/printer", "/smartcard", "/drives",
                  "/drive:hotplug,*", "/drive:mike,/home/mike", "-grab-keyboard", "/network:modem",
                  "-wallpaper", "-themes", "/cache:bitmap:on"):
            self.assertIn(a, pub, a)

    def test_cert_ignore_and_security(self):
        p = prof(enablecredsspsupport=0, administrative_session=1)
        pub, _ = freerdp.build_options(p, freerdp.Credentials("u", None), 3, cert_policy="ignore")
        self.assertIn("/cert:ignore", pub)
        self.assertIn("/sec:nla:off", pub)
        self.assertIn("/admin", pub)
        pub2, _ = freerdp.build_options(p, freerdp.Credentials("u", None), 2)
        self.assertIn("-sec-nla", pub2)

    def test_gateway(self):
        p = prof(gatewayhostname="rdg.example.com", gatewayusagemethod=1, gatewayprofileusagemethod=1,
                 promptcredentialonce=1)
        pub, sec = freerdp.build_options(p, freerdp.Credentials("CORP\\mike", SECRET), 3)
        self.assertTrue(any(a.startswith("/gateway:g:rdg.example.com,usage-method:direct,u:mike,d:CORP,p:")
                            for a in sec))
        self.assertTrue(all(SECRET not in a for a in pub))
        c2 = freerdp.FreeRdp("/usr/bin/xfreerdp", 2)
        plan = freerdp.plan(c2, p, freerdp.Credentials("CORP\\mike", SECRET))
        self.assertIn("/g:rdg.example.com", plan.argv)
        self.assertEqual(plan.stdin_data, (SECRET + "\n" + SECRET + "\n").encode())
        self.assertTrue(all(SECRET not in a for a in plan.argv))
        self.assertNotIn(SECRET, freerdp.display_command(freerdp.plan(freerdp.FreeRdp("x", 3), p,
                                                                      freerdp.Credentials("CORP\\mike", SECRET))))

    def test_extra_args_cannot_smuggle_passwords(self):
        pub, _ = freerdp.build_options(prof(), freerdp.Credentials("u", None), 3,
                                       extra="/p:x /gp:y +home-drive /from-stdin")
        self.assertIn("+home-drive", pub)
        self.assertFalse(any(a.startswith(("/p:", "/gp:", "/from-stdin")) for a in pub))

    def test_newline_rejected(self):
        with self.assertRaises(ValueError):
            freerdp.plan(freerdp.FreeRdp("x", 3), prof(), freerdp.Credentials("u", "a\nb"))

    def test_find_freerdp_and_version(self):
        d = tempfile.mkdtemp()
        fake = os.path.join(d, "xfreerdp")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\necho 'This is FreeRDP version 3.10.3 (n/a)'\n")
        os.chmod(fake, stat.S_IRWXU)
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = d + os.pathsep + "/usr/bin:/bin"
        try:
            c = freerdp.find_freerdp("auto")
            self.assertEqual((c.major, c.version), (3, "3.10.3"))
            with self.assertRaises(freerdp.FreeRdpNotFound):
                freerdp.find_freerdp("/nonexistent/xfreerdp")
        finally:
            os.environ["PATH"] = old


if __name__ == "__main__":
    unittest.main()
