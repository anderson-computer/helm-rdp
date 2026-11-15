import os
import unittest
from pathlib import Path

from tests.helpers import temp_config

from helm_rdp.cli import parse_cli, read_password_fd


class CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_config()

    def test_host_user_port(self):
        qt, o = parse_cli(["helm-rdp", "--host", "pc01", "--user", "CORP\\mike", "--port", "3390", "-platform", "offscreen"])
        self.assertEqual((o["host"], o["user"], o["port"], o["connect"]), ("pc01", "CORP\\mike", 3390, True))
        self.assertEqual(qt, ["helm-rdp", "-platform", "offscreen"])

    def test_host_with_port(self):
        _qt, o = parse_cli(["helm-rdp", "--host", "[fe80::1]:3391"])
        self.assertEqual((o["host"], o["port"]), ("fe80::1", 3391))

    def test_password_fd(self):
        r, w = os.pipe()
        os.write(w, b"pa ss\n")
        os.close(w)
        _qt, o = parse_cli(["helm-rdp", "--host", "pc01", "--user", "mike", "--password-fd", str(r)])
        self.assertEqual(o["password"], "pa ss")
        with self.assertRaises(OSError):
            os.fstat(r)  # closed after reading

    def test_password_fd_refuses_stdout(self):
        with self.assertRaises(ValueError):
            read_password_fd(1)

    def test_mstsc_switches(self):
        _qt, o = parse_cli(["helm-rdp", "/v:pc01:3390", "/f", "/admin"])
        self.assertEqual((o["host"], o["port"], o["fullscreen"], o["admin"]), ("pc01", 3390, True, True))

    def test_rdp_file_and_edit(self):
        path = os.path.join(self.dir, "x.rdp")
        Path(path).write_text("full address:s:pc01\n")
        _qt, o = parse_cli(["helm-rdp", path])
        self.assertEqual((o["file"], o["connect"]), (path, True))
        _qt, o = parse_cli(["helm-rdp", "--edit", path])
        self.assertFalse(o["connect"])

    def test_user_without_host_is_an_error(self):
        with self.assertRaises(SystemExit):
            parse_cli(["helm-rdp", "--user", "mike"])


if __name__ == "__main__":
    unittest.main()
