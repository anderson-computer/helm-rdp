import os
import unittest
from pathlib import Path

from tests.helpers import temp_config

from helm_rdp import rdpfile
from helm_rdp.rdpfile import RdpProfile

MSTSC = ("screen mode id:i:1\r\nuse multimon:i:0\r\ndesktopwidth:i:1280\r\ndesktopheight:i:800\r\n"
         "session bpp:i:24\r\nfull address:s:pc01.corp.example.com:3390\r\nusername:s:CORP\\mike\r\n"
         "password 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB01000000\r\n"
         "audiomode:i:2\r\nredirectclipboard:i:0\r\ndrivestoredirect:s:*\r\n"
         "gatewayhostname:s:rdg.example.com\r\nkdcproxyname:s:\r\nselectedmonitors:s:0,1\r\n"
         "some future key:s:value:with:colons\r\n")


class RdpFileTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_config()

    def test_parse_utf16_mstsc_file(self):
        path = os.path.join(self.dir, "a.rdp")
        with open(path, "wb") as fh:
            fh.write(b"\xff\xfe" + MSTSC.encode("utf-16-le"))
        p = rdpfile.load_rdp(path)
        self.assertEqual(p.address, ("pc01.corp.example.com", 3390))
        self.assertEqual(p.get_str("username"), "CORP\\mike")
        self.assertEqual(p.get_int("screen mode id"), 1)
        self.assertEqual(p.get_int("session bpp"), 24)
        self.assertEqual(p.drives(), ["*"])
        self.assertEqual(p.get_str("some future key"), "value:with:colons")
        self.assertIsNone(p.get("password 51"), "DPAPI password blob must be dropped")

    def test_roundtrip_keeps_unknown_keys_and_order(self):
        p = RdpProfile.from_text(MSTSC)
        out = rdpfile.RdpProfile.from_text(p.to_text())
        self.assertEqual(list(p.items()), list(out.items()))
        self.assertNotIn("password 51", p.to_text())
        self.assertIn("some future key:s:value:with:colons", p.to_text())

    def test_save_is_utf16_bom_crlf(self):
        path = os.path.join(self.dir, "b.rdp")
        p = RdpProfile()
        p.set_address("pc02")
        rdpfile.save_rdp(p, path)
        data = Path(path).read_bytes()
        self.assertTrue(data.startswith(b"\xff\xfe"))
        text = data[2:].decode("utf-16-le")
        self.assertIn("full address:s:pc02\r\n", text)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    def test_utf8_file(self):
        p = RdpProfile.from_text("full address:s:10.0.0.5\nusername:s:mike\n")
        self.assertEqual(p.address, ("10.0.0.5", 3389))

    def test_not_an_rdp_file(self):
        with self.assertRaises(rdpfile.RdpFileError):
            RdpProfile.from_text("hello world\nthis is not rdp\n")

    def test_split_address(self):
        sa = rdpfile.split_address
        self.assertEqual(sa("pc01"), ("pc01", None))
        self.assertEqual(sa("pc01:3390"), ("pc01", 3390))
        self.assertEqual(sa("[fe80::1]:3390"), ("fe80::1", 3390))
        self.assertEqual(sa("fe80::1"), ("fe80::1", None))
        self.assertEqual(sa("rdp://pc01:4000/"), ("pc01", 4000))
        self.assertEqual(rdpfile.join_address("fe80::1", 3390), "[fe80::1]:3390")
        self.assertEqual(rdpfile.join_address("pc01", 3389), "pc01")

    def test_server_port_key(self):
        p = RdpProfile.from_text("full address:s:pc01\nserver port:i:3391\n")
        self.assertEqual(p.address, ("pc01", 3391))

    def test_connection_presets(self):
        p = RdpProfile()
        p.apply_connection_type(1)
        self.assertEqual(p.experience(), [False, False, False, False, False, False, True])
        self.assertEqual(p.get_int("disable wallpaper"), 1)
        p.apply_connection_type(6)
        self.assertEqual(p.experience(), [True] * 7)
        self.assertEqual(p.get_int("networkautodetect"), 0)

    def test_split_user(self):
        self.assertEqual(rdpfile.split_user("CORP\\mike"), ("CORP", "mike"))
        self.assertEqual(rdpfile.split_user("mike@corp.example.com"), ("", "mike@corp.example.com"))


if __name__ == "__main__":
    unittest.main()
