"""Fetch and check the RDP server's TLS certificate before FreeRDP starts.

mstsc shows "The identity of the remote computer cannot be verified" in a
window; FreeRDP asks on the terminal. Helm does the check itself so the
question is a dialog:

  1. TCP connect, send an X.224 Connection Request asking for TLS/NLA
     (RDP_NEG_REQ), read the server's choice (RDP_NEG_RSP).
  2. Start TLS and read the server certificate (no verification).
  3. Try a second, verifying TLS handshake against the system CA store and
     the computer name. If it passes, the certificate is trusted, as mstsc
     would trust it.
  4. Otherwise compare the SHA-256 fingerprint with the ones you accepted
     before (~/.config/helm-rdp/known_certs.json).

Whatever you accept is pinned for FreeRDP with /cert:deny,fingerprint:
sha256:<hash>, so FreeRDP refuses any other certificate and never prompts.

No Qt here, so it is unit tested headless.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import socket
import ssl
import struct
from typing import Dict, List, Optional

from .config import atomic_write, known_certs_path

PROTOCOL_RDP = 0
PROTOCOL_SSL = 0x1
PROTOCOL_HYBRID = 0x2
PROTOCOL_HYBRID_EX = 0x8

NEG_FAILURES = {
    1: "The server requires TLS security (SSL_REQUIRED_BY_SERVER).",
    2: "The server only allows standard RDP security (SSL_NOT_ALLOWED_BY_SERVER).",
    3: "The server has no TLS certificate (SSL_CERT_NOT_ON_SERVER).",
    4: "Inconsistent security flags (INCONSISTENT_FLAGS).",
    5: "The server requires Network Level Authentication (HYBRID_REQUIRED_BY_SERVER).",
    6: "The server requires TLS with user authentication (SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER).",
}


class CertCheckError(Exception):
    """The server could not be reached or did not speak RDP."""


class CertInfo:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.protocol = PROTOCOL_RDP        # what the server selected
        self.der: Optional[bytes] = None
        self.trusted = False                 # passed the system CA + name check
        self.trust_error = ""                # why not, from OpenSSL
        self.subject = ""
        self.issuer = ""
        self.names: List[str] = []           # CN + DNS SANs
        self.not_before = ""
        self.not_after = ""
        self.expired = False
        self.self_signed = False

    @property
    def has_cert(self) -> bool:
        return self.der is not None

    @property
    def sha256(self) -> str:
        """Lower-case colon-separated hex, the form FreeRDP uses."""
        if self.der is None:
            return ""
        h = hashlib.sha256(self.der).hexdigest()
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))

    @property
    def sha1(self) -> str:
        if self.der is None:
            return ""
        h = hashlib.sha1(self.der).hexdigest()  # nosec - display only, like mstsc's "Thumbprint"
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))

    @property
    def name_matches(self) -> bool:
        return any(_name_match(n, self.host) for n in self.names)

    def problems(self) -> List[str]:
        """mstsc-style list of certificate errors."""
        out = []
        if not self.has_cert:
            return out
        if self.self_signed or not self.trusted:
            out.append("The certificate is not from a trusted certifying authority.")
        if not self.name_matches:
            out.append("The name in the certificate does not match the computer you are "
                       "connecting to (%s)." % self.host)
        if self.expired:
            out.append("The certificate has expired or is not yet valid.")
        return out


def _name_match(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*.") and "." in host:
        return host.split(".", 1)[1] == pattern[2:]
    # mstsc also accepts the short computer name for a FQDN certificate.
    return "." not in host and pattern.split(".", 1)[0] == host


def x224_connection_request(cookie: str = "", protocols: int = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX) -> bytes:
    body = b""
    if cookie:
        body += ("Cookie: mstshash=%s\r\n" % cookie[:9]).encode("ascii", "ignore")
    body += struct.pack("<BBHI", 0x01, 0x00, 8, protocols)  # RDP_NEG_REQ
    x224 = struct.pack("!BBHHB", 6 + len(body), 0xE0, 0, 0, 0) + body
    return struct.pack("!BBH", 3, 0, 4 + len(x224)) + x224


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise CertCheckError("The connection was closed by the remote computer.")
        buf += chunk
    return buf


def parse_connection_confirm(data: bytes) -> int:
    """Selected protocol from an X.224 Connection Confirm (TPKT payload)."""
    if len(data) < 7 or data[1] & 0xF0 != 0xD0:
        raise CertCheckError("The remote computer did not answer like an RDP server.")
    li = data[0]
    neg = data[7:1 + li]
    if len(neg) >= 8:
        typ, _flags, _length, value = struct.unpack("<BBHI", neg[:8])
        if typ == 0x02:
            return value
        if typ == 0x03:
            raise CertCheckError(NEG_FAILURES.get(value, "Security negotiation failed (code %d)." % value))
    return PROTOCOL_RDP  # old server, standard RDP security


def _negotiate(host: str, port: int, timeout: float) -> "tuple":
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror as e:
        raise CertCheckError("DNS: %s" % (e.strerror or e)) from e
    except OSError as e:
        raise CertCheckError("CONNECT: %s" % (e.strerror or e)) from e
    try:
        sock.sendall(x224_connection_request())
        hdr = _recv_exact(sock, 4)
        if hdr[0] != 3:
            raise CertCheckError("The remote computer did not answer like an RDP server.")
        length = struct.unpack("!H", hdr[2:4])[0]
        if length < 11 or length > 4096:
            raise CertCheckError("The remote computer did not answer like an RDP server.")
        proto = parse_connection_confirm(_recv_exact(sock, length - 4))
        return sock, proto
    except socket.timeout as e:
        sock.close()
        raise CertCheckError("The remote computer did not answer in time.") from e
    except OSError as e:
        sock.close()
        raise CertCheckError("CONNECT: %s" % (e.strerror or e)) from e
    except CertCheckError:
        sock.close()
        raise


def _insecure_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch(host: str, port: int = 3389, timeout: float = 10.0, verify: bool = True) -> CertInfo:
    info = CertInfo(host, port)
    sock, proto = _negotiate(host, port, timeout)
    info.protocol = proto
    try:
        if proto == PROTOCOL_RDP:
            return info
        try:
            with _insecure_context().wrap_socket(sock, server_hostname=host if _is_name(host) else None) as tls:
                info.der = tls.getpeercert(binary_form=True)
        except (ssl.SSLError, OSError) as e:
            raise CertCheckError("TLS: %s" % e) from e
    finally:
        try:
            sock.close()
        except OSError:
            pass
    _describe(info)
    if verify:
        _verify(info, timeout)
    return info


def _is_name(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return False
    except OSError:
        return True


def _verify(info: CertInfo, timeout: float) -> None:
    """Second handshake with full verification (system CAs + host name)."""
    ctx = ssl.create_default_context()
    if not _is_name(info.host):
        ctx.check_hostname = False
    try:
        sock, proto = _negotiate(info.host, info.port, timeout)
    except CertCheckError as e:
        info.trust_error = str(e)
        return
    try:
        if proto == PROTOCOL_RDP:
            return
        with ctx.wrap_socket(sock, server_hostname=info.host if _is_name(info.host) else None) as tls:
            if tls.getpeercert(binary_form=True) == info.der:
                info.trusted = _is_name(info.host) or info.name_matches
    except ssl.SSLCertVerificationError as e:
        info.trust_error = e.verify_message or str(e)
    except (ssl.SSLError, OSError) as e:
        info.trust_error = str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _describe(info: CertInfo) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID
    except ImportError:  # pragma: no cover - cryptography is a hard Requires
        return
    try:
        cert = x509.load_der_x509_certificate(info.der, default_backend())
    except ValueError:
        return
    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.self_signed = cert.subject == cert.issuer
    names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names += san.get_values_for_type(x509.DNSName)
        names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    seen = []
    for n in names:
        if n not in seen:
            seen.append(n)
    info.names = seen
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    info.expired = not (nb <= now <= na)
    info.not_before = nb.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    info.not_after = na.astimezone().strftime("%Y-%m-%d %H:%M %Z")


# ---------------------------------------------------------------------------
# Accepted certificates ("Don't ask me again for connections to this computer")
# ---------------------------------------------------------------------------
def _key(host: str, port: int) -> str:
    return "%s:%d" % (host.lower(), int(port))


def load_known(path: Optional[str] = None) -> Dict[str, Dict]:
    try:
        with open(path or known_certs_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_known(known: Dict[str, Dict], path: Optional[str] = None) -> None:
    atomic_write(path or known_certs_path(), json.dumps(known, indent=2, sort_keys=True))


def known_fingerprint(host: str, port: int, known: Optional[Dict] = None) -> str:
    entry = (known if known is not None else load_known()).get(_key(host, port))
    return entry.get("sha256", "") if isinstance(entry, dict) else ""


def remember(info: CertInfo, path: Optional[str] = None) -> None:
    known = load_known(path)
    known[_key(info.host, info.port)] = {
        "sha256": info.sha256, "subject": info.subject, "issuer": info.issuer,
        "not_after": info.not_after,
        "accepted": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
    }
    save_known(known, path)


def forget(key: str, path: Optional[str] = None) -> None:
    known = load_known(path)
    if known.pop(key, None) is not None:
        save_known(known, path)


# Decision for one connection ----------------------------------------------
TRUSTED, KNOWN, ASK, CHANGED, NO_CERT = "trusted", "known", "ask", "changed", "no-cert"


def classify(info: CertInfo, known: Optional[Dict] = None) -> str:
    if not info.has_cert:
        return NO_CERT
    if info.trusted:
        return TRUSTED
    pinned = known_fingerprint(info.host, info.port, known)
    if pinned and pinned == info.sha256:
        return KNOWN
    if pinned:
        return CHANGED
    return ASK
