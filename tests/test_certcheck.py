"""certcheck against a fake RDP server on 127.0.0.1 (X.224 + TLS)."""

import datetime
import os
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from tests.helpers import temp_config

from helm_rdp import certcheck


def make_cert(d, cn="FAKE-RDP"):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256(), default_backend()))
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    Path(cp).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(kp).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cp, kp, cert.public_bytes(serialization.Encoding.DER)


class FakeRdp(threading.Thread):
    """mode: tls | rdp (no negotiation data) | fail (RDP_NEG_FAILURE 5)."""

    def __init__(self, mode, cert=None, key=None):
        super().__init__(daemon=True)
        self.mode = mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.ctx = None
        if cert:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(cert, key)
        self.requests = []

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                hdr = c.recv(4)
                body = c.recv(struct.unpack("!H", hdr[2:4])[0] - 4)
                self.requests.append(body)
                if self.mode == "rdp":
                    cc = struct.pack("!BBHHB", 6, 0xD0, 0, 0x1234, 0)
                elif self.mode == "fail":
                    cc = struct.pack("!BBHHB", 14, 0xD0, 0, 0x1234, 0) + struct.pack("<BBHI", 3, 0, 8, 5)
                else:
                    cc = struct.pack("!BBHHB", 14, 0xD0, 0, 0x1234, 0) + struct.pack("<BBHI", 2, 0, 8, 1)
                c.sendall(struct.pack("!BBH", 3, 0, 4 + len(cc)) + cc)
                if self.mode == "tls":
                    t = self.ctx.wrap_socket(c, server_side=True)
                    t.close()
                else:
                    c.close()
            except (OSError, ssl.SSLError):
                pass

    def stop(self):
        self.sock.close()


class CertCheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = temp_config()

    def test_tls_self_signed(self):
        cp, kp, der = make_cert(self.dir)
        srv = FakeRdp("tls", cp, kp)
        srv.start()
        try:
            info = certcheck.fetch("127.0.0.1", srv.port, timeout=5)
        finally:
            srv.stop()
        self.assertEqual(info.protocol, certcheck.PROTOCOL_SSL)
        self.assertEqual(info.der, der)
        self.assertEqual(len(info.sha256.split(":")), 32)
        self.assertEqual(info.names, ["FAKE-RDP"])
        self.assertTrue(info.self_signed)
        self.assertFalse(info.trusted)
        self.assertTrue(any("trusted certifying authority" in p for p in info.problems()))
        self.assertTrue(any("does not match" in p for p in info.problems()))
        # request carried RDP_NEG_REQ asking for TLS + NLA
        req = srv.requests[0]
        self.assertEqual(req[1], 0xE0)
        self.assertEqual(struct.unpack("<BBHI", req[-8:]), (1, 0, 8, 0xB))
        # pinning
        self.assertEqual(certcheck.classify(info), certcheck.ASK)
        certcheck.remember(info)
        self.assertEqual(certcheck.classify(info), certcheck.KNOWN)
        known = certcheck.load_known()
        known["127.0.0.1:%d" % srv.port]["sha256"] = "00:" * 31 + "00"
        certcheck.save_known(known)
        self.assertEqual(certcheck.classify(info), certcheck.CHANGED)
        certcheck.forget("127.0.0.1:%d" % srv.port)
        self.assertEqual(certcheck.load_known(), {})

    def test_standard_rdp_security(self):
        srv = FakeRdp("rdp")
        srv.start()
        try:
            info = certcheck.fetch("127.0.0.1", srv.port, timeout=5)
        finally:
            srv.stop()
        self.assertFalse(info.has_cert)
        self.assertEqual(certcheck.classify(info), certcheck.NO_CERT)

    def test_negotiation_failure(self):
        srv = FakeRdp("fail")
        srv.start()
        try:
            with self.assertRaises(certcheck.CertCheckError) as cm:
                certcheck.fetch("127.0.0.1", srv.port, timeout=5)
        finally:
            srv.stop()
        self.assertIn("Network Level Authentication", str(cm.exception))

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(certcheck.CertCheckError) as cm:
            certcheck.fetch("127.0.0.1", port, timeout=3)
        self.assertTrue(str(cm.exception).startswith("CONNECT:"))

    def test_name_match(self):
        nm = certcheck._name_match
        self.assertTrue(nm("pc01.corp.example.com", "pc01.corp.example.com"))
        self.assertTrue(nm("*.corp.example.com", "pc01.corp.example.com"))
        self.assertTrue(nm("PC01.corp.example.com", "pc01"))
        self.assertFalse(nm("pc02.corp.example.com", "pc01.corp.example.com"))


if __name__ == "__main__":
    unittest.main()
