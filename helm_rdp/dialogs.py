"""mstsc-style dialogs: credentials, certificate warning, connecting,
remote audio, local devices, RD Gateway and saved certificates."""

from __future__ import annotations

import html
import os
from typing import Dict, List, Optional

from . import APP_NAME
from . import certcheck
from .qtcompat import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QIcon,
    QLabel,
    QLayout,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QStyle,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    Qt,
    qenum,
)

RED = "#c42b1c"


def _esc(s) -> str:
    return html.escape(str(s or ""))


def _std_icon(widget: QWidget, name: str, size: int = 32):
    return widget.style().standardIcon(qenum(QStyle, name)).pixmap(size, size)


def _ok_cancel(dialog: QDialog, ok_text: str = "OK") -> QDialogButtonBox:
    box = QDialogButtonBox()
    ok = box.addButton(ok_text, qenum(QDialogButtonBox, "AcceptRole"))
    ok.setDefault(True)
    box.addButton(qenum(QDialogButtonBox, "Cancel"))
    box.accepted.connect(dialog.accept)
    box.rejected.connect(dialog.reject)
    dialog.ok_button = ok
    return box


# ---------------------------------------------------------------------------
# Credentials ("Windows Security" in mstsc)
# ---------------------------------------------------------------------------
class CredentialsDialog(QDialog):
    def __init__(self, parent, host: str, username: str = "", message: str = "",
                 remember_label: Optional[str] = "system keychain", remember_checked: bool = False,
                 need_user: bool = True):
        super().__init__(parent)
        self.setWindowTitle("%s Security" % "Helm")
        self.setModal(True)
        self.setMinimumWidth(430)
        lay = QVBoxLayout(self)
        head = QLabel("<span style='font-size:14pt'>Enter your credentials</span>")
        lay.addWidget(head)
        sub = QLabel("These credentials will be used to connect to %s." % _esc(host))
        sub.setWordWrap(True)
        lay.addWidget(sub)
        self.message = QLabel("<span style='color:%s'>%s</span>" % (RED, _esc(message)))
        self.message.setWordWrap(True)
        self.message.setVisible(bool(message))
        lay.addWidget(self.message)
        form = QFormLayout()
        self.username = QLineEdit(username or "")
        self.username.setPlaceholderText("User name, DOMAIN\\user or user@domain")
        self.username.setEnabled(need_user)
        form.addRow("User name:", self.username)
        self.password = QLineEdit()
        self.password.setEchoMode(qenum(QLineEdit, "Password"))
        self.password.setPlaceholderText("Password")
        form.addRow("Password:", self.password)
        lay.addLayout(form)
        self.remember = QCheckBox("Remember me" + (" (%s)" % remember_label if remember_label else ""))
        self.remember.setChecked(bool(remember_checked and remember_label))
        self.remember.setVisible(remember_label is not None)
        lay.addWidget(self.remember)
        lay.addWidget(_ok_cancel(self))
        self.username.textChanged.connect(self._validate)
        (self.password if username else self.username).setFocus()
        self._validate()

    def _validate(self, *_a) -> None:
        self.ok_button.setEnabled(bool(self.username.text().strip()))

    def values(self):
        return self.username.text().strip(), self.password.text(), self.remember.isChecked()


# ---------------------------------------------------------------------------
# Certificate warning
# ---------------------------------------------------------------------------
class CertificateDialog(QDialog):
    """mstsc's "The identity of the remote computer cannot be verified".

    Result: accept_mode is "once" (Yes), "always" (Yes + Don't ask me again)
    or None (No)."""

    def __init__(self, parent, info: certcheck.CertInfo, changed: bool = False, old_fp: str = ""):
        super().__init__(parent)
        self.info = info
        self.accept_mode: Optional[str] = None
        self.setWindowTitle("Remote Desktop Connection")
        self.setModal(True)
        self.setFixedWidth(660)
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(_std_icon(self, "SP_MessageBoxWarning", 40))
        icon.setAlignment(qenum(Qt, "AlignTop"))
        top.addWidget(icon)
        if changed:
            title = ("<b>The certificate of the remote computer has changed.</b><br>"
                     "It is not the certificate you accepted before. This can happen after "
                     "the computer was rebuilt or its certificate renewed, but it can also "
                     "mean someone is intercepting the connection.")
        else:
            title = ("<b>The identity of the remote computer cannot be verified. "
                     "Do you want to connect anyway?</b><br>"
                     "The remote computer could not be authenticated due to problems with its "
                     "security certificate. It may be unsafe to proceed.")
        t = QLabel(title)
        t.setWordWrap(True)
        top.addWidget(t, 1)
        lay.addLayout(top)

        g1 = QGroupBox("Certificate name")
        l1 = QVBoxLayout(g1)
        l1.addWidget(QLabel("Name in the certificate from the remote computer:"))
        self.cert_name = QLabel("<b>%s</b>" % _esc(", ".join(info.names) or info.subject or "(none)"))
        self.cert_name.setTextInteractionFlags(qenum(Qt, "TextSelectableByMouse"))
        l1.addWidget(self.cert_name)
        lay.addWidget(g1)

        g2 = QGroupBox("Certificate errors")
        l2 = QVBoxLayout(g2)
        intro = QLabel("The following errors were encountered while validating the remote "
                       "computer's certificate:")
        intro.setWordWrap(True)
        l2.addWidget(intro)
        problems = info.problems()
        if changed:
            problems.insert(0, "The certificate does not match the one you accepted before.")
        plist = QLabel("".join("<p style='margin:2px 0'>&#9888;&nbsp; %s</p>" % _esc(p) for p in problems)
                       or "<p>(none)</p>")
        plist.setWordWrap(True)
        l2.addWidget(plist)
        self.problem_label = plist
        lay.addWidget(g2)

        fp = QLabel("SHA-256 fingerprint:<br><tt>%s</tt>%s" % (
            _fp_lines(info.sha256),
            ("<br><span style='color:%s'>Previously accepted:<br><tt>%s</tt></span>" % (RED, _fp_lines(old_fp)))
            if changed and old_fp else ""))
        fp.setWordWrap(True)
        fp.setTextInteractionFlags(qenum(Qt, "TextSelectableByMouse"))
        lay.addWidget(fp)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlainText(certificate_text(info))
        self.details.setVisible(False)
        self.details.setMinimumHeight(170)
        lay.addWidget(self.details)

        q = QLabel("Do you want to connect despite these certificate errors?")
        lay.addWidget(q)
        self.dont_ask = QCheckBox("Don't ask me again for connections to this computer")
        lay.addWidget(self.dont_ask)

        row = QHBoxLayout()
        self.view_btn = QPushButton("View certificate...")
        self.view_btn.clicked.connect(self._toggle_details)
        row.addWidget(self.view_btn)
        row.addStretch(1)
        self.yes_btn = QPushButton("Yes")
        self.no_btn = QPushButton("No")
        self.no_btn.setDefault(True)  # safe default, like mstsc
        self.yes_btn.clicked.connect(self._yes)
        self.no_btn.clicked.connect(self.reject)
        row.addWidget(self.yes_btn)
        row.addWidget(self.no_btn)
        lay.addLayout(row)

    def _toggle_details(self) -> None:
        self.details.setVisible(not self.details.isVisible())
        self.view_btn.setText("Hide certificate" if self.details.isVisible() else "View certificate...")
        self.adjustSize()

    def _yes(self) -> None:
        self.accept_mode = "always" if self.dont_ask.isChecked() else "once"
        self.accept()


def _fp_lines(fp: str) -> str:
    """Fingerprint in two lines of 16 bytes, upper case."""
    parts = (fp or "").upper().split(":")
    return _esc(":".join(parts[:16])) + ("<br>" + _esc(":".join(parts[16:])) if len(parts) > 16 else "")


def certificate_text(info: certcheck.CertInfo) -> str:
    proto = {certcheck.PROTOCOL_SSL: "TLS", certcheck.PROTOCOL_HYBRID: "TLS + CredSSP (NLA)",
             certcheck.PROTOCOL_HYBRID_EX: "TLS + CredSSP (NLA, early user auth)"}.get(info.protocol, str(info.protocol))
    return "\n".join([
        "Computer:        %s:%d" % (info.host, info.port),
        "Security:        %s" % proto,
        "Issued to:       %s" % info.subject,
        "Issued by:       %s" % info.issuer,
        "Names:           %s" % ", ".join(info.names),
        "Valid from:      %s" % info.not_before,
        "Valid to:        %s" % info.not_after,
        "SHA-256:         %s" % info.sha256.upper(),
        "SHA-1 thumbprint: %s" % info.sha1.upper(),
        "System CA check: %s" % ("trusted" if info.trusted else (info.trust_error or "not trusted")),
    ])


# ---------------------------------------------------------------------------
# Connecting
# ---------------------------------------------------------------------------
class ConnectingDialog(QDialog):
    def __init__(self, parent, host: str):
        super().__init__(parent)
        self.setWindowTitle("Remote Desktop Connection")
        self.setModal(False)
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)
        self.title = QLabel("<b>Connecting to:</b><br>%s" % _esc(host))
        lay.addWidget(self.title)
        self.step = QLabel("Initiating remote connection...")
        lay.addWidget(self.step)
        bar = QProgressBar()
        bar.setRange(0, 0)
        bar.setTextVisible(False)
        bar.setMaximumHeight(14)
        lay.addWidget(bar)
        row = QHBoxLayout()
        row.addStretch(1)
        self.cancel_btn = QPushButton("Cancel")
        row.addWidget(self.cancel_btn)
        lay.addLayout(row)

    def set_step(self, text: str) -> None:
        self.step.setText(text)


# ---------------------------------------------------------------------------
# Local Resources ▸ Remote audio Settings...
# ---------------------------------------------------------------------------
class AudioDialog(QDialog):
    def __init__(self, parent, audiomode: int, capture: bool):
        super().__init__(parent)
        self.setWindowTitle("Remote Desktop Connection - Remote audio")
        lay = QVBoxLayout(self)
        g1 = QGroupBox("Remote audio playback")
        l1 = QVBoxLayout(g1)
        self.play = QButtonGroup(self)
        for mode, text in ((0, "Play on this computer"), (2, "Do not play"), (1, "Play on remote computer")):
            rb = QRadioButton(text)
            rb.setChecked(mode == audiomode)
            self.play.addButton(rb, mode)
            l1.addWidget(rb)
        lay.addWidget(g1)
        g2 = QGroupBox("Remote audio recording")
        l2 = QVBoxLayout(g2)
        self.rec = QButtonGroup(self)
        for mode, text in ((1, "Record from this computer"), (0, "Do not record")):
            rb = QRadioButton(text)
            rb.setChecked(mode == (1 if capture else 0))
            self.rec.addButton(rb, mode)
            l2.addWidget(rb)
        lay.addWidget(g2)
        lay.addWidget(_ok_cancel(self))

    def values(self):
        return self.play.checkedId(), self.rec.checkedId() == 1


# ---------------------------------------------------------------------------
# Local Resources ▸ More... (drives, smart cards)
# ---------------------------------------------------------------------------
def local_drives() -> List[tuple]:
    """(label, path) for the home folder and mounted removable media."""
    home = os.path.expanduser("~")
    out = [("Home folder (%s)" % home, home)]
    user = os.environ.get("USER", "")
    for base in ("/run/media/%s" % user, "/media/%s" % user, "/media", "/mnt"):
        try:
            for name in sorted(os.listdir(base)):
                p = os.path.join(base, name)
                if os.path.isdir(p) and os.path.ismount(p) and all(p != q for _l, q in out):
                    out.append(("%s (%s)" % (name, p), p))
        except OSError:
            continue
    return out


class DevicesDialog(QDialog):
    def __init__(self, parent, smartcards: bool, drives: List[str]):
        super().__init__(parent)
        self.setWindowTitle("Remote Desktop Connection - Local devices and resources")
        self.setMinimumWidth(480)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Choose the devices and resources on this computer that you want "
                             "to use in your remote session."))
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.smart = QTreeWidgetItem(["Smart cards"])
        self.smart.setCheckState(0, qenum(Qt, "Checked") if smartcards else qenum(Qt, "Unchecked"))
        self.tree.addTopLevelItem(self.smart)
        self.drives_item = QTreeWidgetItem(["Drives"])
        self.tree.addTopLevelItem(self.drives_item)
        chosen = set(drives)
        self.items = []
        entries = [("All mounted drives", "*")] + local_drives() + [("Drives that I connect to later", "DynamicDrives")]
        known = {p for _l, p in entries}
        entries += [("%s" % d, d) for d in drives if d not in known]
        for label, path in entries:
            it = QTreeWidgetItem([label])
            it.setData(0, qenum(Qt, "UserRole"), path)
            it.setCheckState(0, qenum(Qt, "Checked") if path in chosen else qenum(Qt, "Unchecked"))
            self.drives_item.addChild(it)
            self.items.append(it)
        self.drives_item.setExpanded(True)
        lay.addWidget(self.tree, 1)
        row = QHBoxLayout()
        add = QPushButton("Add folder...")
        add.clicked.connect(self._add)
        row.addWidget(add)
        row.addStretch(1)
        lay.addLayout(row)
        note = QLabel("Serial ports, video capture devices and other plug-and-play devices "
                      "are not redirected by Helm.")
        note.setWordWrap(True)
        note.setEnabled(False)
        lay.addWidget(note)
        lay.addWidget(_ok_cancel(self))
        self.resize(520, 420)

    def _add(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose a folder to share", os.path.expanduser("~"))
        if path:
            it = QTreeWidgetItem([path])
            it.setData(0, qenum(Qt, "UserRole"), path)
            it.setCheckState(0, qenum(Qt, "Checked"))
            self.drives_item.addChild(it)
            self.items.append(it)

    def values(self):
        drives = [it.data(0, qenum(Qt, "UserRole")) for it in self.items
                  if it.checkState(0) == qenum(Qt, "Checked")]
        return self.smart.checkState(0) == qenum(Qt, "Checked"), drives


# ---------------------------------------------------------------------------
# Advanced ▸ Connect from anywhere ▸ Settings...
# ---------------------------------------------------------------------------
class GatewayDialog(QDialog):
    """RD Gateway Server Settings."""

    def __init__(self, parent, profile):
        super().__init__(parent)
        self.setWindowTitle("RD Gateway Server Settings")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        g = QGroupBox("Connection settings")
        gl = QVBoxLayout(g)
        self.auto = QRadioButton("Automatically detect RD Gateway server settings")
        self.use = QRadioButton("Use these RD Gateway server settings:")
        self.none = QRadioButton("Do not use an RD Gateway server")
        form = QFormLayout()
        self.server = QLineEdit(profile.get_str("gatewayhostname"))
        self.server.setPlaceholderText("gateway.example.com[:443]")
        self.method = QComboBox()
        self.method.addItem("Ask for password (NTLM)", 0)
        self.method.addItem("Allow me to select later", 4)
        idx = self.method.findData(profile.get_int("gatewaycredentialssource", 4))
        self.method.setCurrentIndex(max(0, idx))
        self.bypass = QCheckBox("Bypass RD Gateway server for local addresses")
        form.addRow("Server name:", self.server)
        form.addRow("Logon method:", self.method)
        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(24, 0, 0, 0)
        il.addLayout(form)
        il.addWidget(self.bypass)
        gl.addWidget(self.auto)
        gl.addWidget(self.use)
        gl.addWidget(inner)
        gl.addWidget(self.none)
        lay.addWidget(g)
        g2 = QGroupBox("Logon settings")
        g2l = QVBoxLayout(g2)
        self.same = QCheckBox("Use my RD Gateway credentials for the remote computer")
        self.same.setChecked(profile.get_bool("promptcredentialonce"))
        g2l.addWidget(self.same)
        lay.addWidget(g2)
        usage = profile.get_int("gatewayusagemethod", 4)
        explicit = profile.get_int("gatewayprofileusagemethod", 0) == 1
        if explicit and usage in (1, 2):
            self.use.setChecked(True)
            self.bypass.setChecked(usage == 2)
        elif explicit and usage == 0:
            self.none.setChecked(True)
        else:
            self.auto.setChecked(True)
            self.bypass.setChecked(True)
        note = QLabel("Automatic detection is not available on Linux: Helm connects directly "
                      "unless you enter a gateway here.")
        note.setWordWrap(True)
        note.setEnabled(False)
        lay.addWidget(note)
        lay.addWidget(_ok_cancel(self))
        for rb in (self.auto, self.use, self.none):
            rb.toggled.connect(self._sync)
        self._sync()

    def _sync(self, *_a) -> None:
        on = self.use.isChecked()
        for w in (self.server, self.method, self.bypass):
            w.setEnabled(on)

    def apply_to(self, profile) -> None:
        if self.use.isChecked() and self.server.text().strip():
            profile.set("gatewayhostname", self.server.text().strip(), "s")
            profile.set("gatewayusagemethod", 2 if self.bypass.isChecked() else 1, "i")
            profile.set("gatewayprofileusagemethod", 1, "i")
        elif self.none.isChecked():
            profile.set("gatewayusagemethod", 0, "i")
            profile.set("gatewayprofileusagemethod", 1, "i")
        else:
            profile.set("gatewayusagemethod", 4, "i")
            profile.set("gatewayprofileusagemethod", 0, "i")
        profile.set("gatewaycredentialssource", int(self.method.currentData()), "i")
        profile.set("promptcredentialonce", 1 if self.same.isChecked() else 0, "i")


# ---------------------------------------------------------------------------
# Options ▸ Saved Certificates...
# ---------------------------------------------------------------------------
class KnownCertsDialog(QDialog):
    def __init__(self, parent, path: Optional[str] = None):
        super().__init__(parent)
        self.path = path
        self.setWindowTitle("Saved Certificates — %s" % APP_NAME)
        self.resize(760, 360)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Server certificates you chose to trust (\"Don't ask me again\")."))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Computer", "Issued to", "Expires", "Accepted", "SHA-256"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)
        row = QHBoxLayout()
        self.remove_btn = QPushButton("Remove")
        self.remove_btn.clicked.connect(self._remove)
        row.addWidget(self.remove_btn)
        row.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)
        self._load()

    def _load(self) -> None:
        self.tree.clear()
        for key, e in sorted(certcheck.load_known(self.path).items()):
            it = QTreeWidgetItem([key, e.get("subject", ""), e.get("not_after", ""),
                                  e.get("accepted", ""), e.get("sha256", "").upper()])
            it.setData(0, qenum(Qt, "UserRole"), key)
            self.tree.addTopLevelItem(it)
        for i in range(4):
            self.tree.resizeColumnToContents(i)

    def _remove(self) -> None:
        for it in self.tree.selectedItems():
            certcheck.forget(it.data(0, qenum(Qt, "UserRole")), self.path)
        self._load()


class SessionLogDialog(QDialog):
    def __init__(self, parent, title: str, text: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 460)
        lay = QVBoxLayout(self)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setPlainText(text)
        view.setLineWrapMode(qenum(QPlainTextEdit, "NoWrap"))
        lay.addWidget(view)
        box = QDialogButtonBox(qenum(QDialogButtonBox, "Close"))
        box.rejected.connect(self.close)
        box.accepted.connect(self.close)
        lay.addWidget(box)
