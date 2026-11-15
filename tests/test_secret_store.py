import os
import unittest
from pathlib import Path

from tests.helpers import temp_config

from helm_rdp import config, secret_store
from helm_rdp.secret_store import FileVault, VaultError


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_config()

    def test_vault_roundtrip(self):
        path = os.path.join(self.dir, "vault.json")
        v = FileVault(path)
        FileVault.SCRYPT_N = 2 ** 12  # fast for tests
        v.create("master-password")
        v.set(secret_store.target_name("PC01"), "hunter2")
        raw = Path(path).read_text()
        self.assertNotIn("hunter2", raw)
        self.assertIn("helm-rdp-vault", raw)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        v2 = FileVault(path)
        with self.assertRaises(VaultError):
            v2.unlock("wrong-password")
        v2.unlock("master-password")
        self.assertEqual(v2.get("TERMSRV/pc01"), "hunter2")
        v2.change_master("master-password", "another-master")
        v3 = FileVault(path)
        v3.unlock("another-master")
        self.assertEqual(v3.get("TERMSRV/pc01"), "hunter2")

    def test_short_master_refused(self):
        with self.assertRaises(VaultError):
            FileVault(os.path.join(self.dir, "v.json")).create("short")

    def test_keyring_without_session_bus(self):
        old = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/nonexistent/bus"
        try:
            ring = secret_store.KeyringStore()
            self.assertFalse(ring.available)
            self.assertTrue(ring.error)
            self.assertEqual(secret_store.auto_backend(ring.available), secret_store.BACKEND_VAULT)
        finally:
            if old is None:
                os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
            else:
                os.environ["DBUS_SESSION_BUS_ADDRESS"] = old

    def test_labels_match_skiff_wording(self):
        self.assertEqual(secret_store.BACKEND_LABELS["keyring"], "System keychain (GNOME Keyring / Secret Service)")
        self.assertEqual(secret_store.BACKEND_LABELS["vault"], "Encrypted vault file (master password)")


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_config()

    def test_recent(self):
        s = config.default_settings()
        for h in ["a", "b", "A", "c"]:
            config.add_recent(s, h, "u-" + h)
        self.assertEqual([r["host"] for r in s["recent"]], ["c", "A", "b"])
        self.assertEqual(config.recent_username(s, "a"), "u-A")
        config.save_settings(s)
        self.assertEqual(config.load_settings()["recent"], s["recent"])

    def test_master_conf_override(self):
        m = os.path.join(self.dir, "master.conf")
        u = os.path.join(self.dir, "user.conf")
        Path(m).write_text("[helm-rdp]\nfreerdp = /usr/bin/xfreerdp\nlog_level = WARN\n")
        Path(u).write_text("[helm-rdp]\nlog_level = INFO\n")
        c = config.load_master([m, u])
        self.assertEqual((c["freerdp"], c["log_level"], c["connect_timeout"]), ("/usr/bin/xfreerdp", "INFO", "15"))


if __name__ == "__main__":
    unittest.main()
