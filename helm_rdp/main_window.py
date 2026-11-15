"""The Remote Desktop Connection window (mstsc layout) and the connect flow."""

from __future__ import annotations

import html
import os
import threading
import time
from typing import Dict, List, Optional

from . import APP_NAME, APP_ID, __version__
from . import certcheck, config, freerdp, rdpfile
from .dialogs import (
    AudioDialog,
    CertificateDialog,
    ConnectingDialog,
    CredentialsDialog,
    DevicesDialog,
    GatewayDialog,
    KnownCertsDialog,
    SessionLogDialog,
)
from .passwords import PasswordManager, PasswordOptionsDialog, _accepted
from .qtcompat import (
    QAction,
    QCheckBox,
    QColor,
    QComboBox,
    QDialog,
    QFileDialog,
    QFont,
    QGridLayout,
    QGroupBox,
    QGuiApplication,
    QHBoxLayout,
    QIcon,
    QKeySequence,
    QLabel,
    QLinearGradient,
    QMainWindow,
    QMenu,
    QMessageBox,
    QObject,
    QPainter,
    QPushButton,
    QSizePolicy,
    QSlider,
    QStyle,
    QTabWidget,
    QTimer,
    QVBoxLayout,
    QWidget,
    Qt,
    exec_,
    pyqtSignal,
    qenum,
)
from .rdpfile import CONNECTION_TYPES, RdpFileError, RdpProfile, join_address
from .session import Outcome, Session, classify

RESOLUTIONS = [(640, 480), (800, 600), (1024, 768), (1152, 864), (1280, 720), (1280, 768),
               (1280, 800), (1280, 1024), (1360, 768), (1366, 768), (1440, 900), (1600, 900),
               (1600, 1200), (1680, 1050), (1920, 1080), (1920, 1200), (2560, 1440),
               (2560, 1600), (3440, 1440), (3840, 2160)]
COLOR_DEPTHS = [(15, "High Color (15 bit)"), (16, "High Color (16 bit)"),
                (24, "True Color (24 bit)"), (32, "Highest Quality (32 bit)")]
KEYBOARD_HOOK = [(0, "On this computer"), (1, "On the remote computer"),
                 (2, "Only when using the full screen")]
AUTH_LEVELS = [(0, "Connect and don't warn me"), (2, "Warn me"), (1, "Do not connect")]
EXPERIENCE_LABELS = ["Desktop background", "Font smoothing", "Desktop composition",
                     "Show window contents while dragging", "Menu and window animation",
                     "Visual styles", "Persistent bitmap caching"]
MAX_LOGON_TRIES = 3


class Banner(QWidget):
    """Blue strip with the logo and "Remote Desktop / Connection"."""

    def __init__(self, icon: QIcon, parent=None):
        super().__init__(parent)
        self.icon = icon
        self.setFixedHeight(68)
        self.setSizePolicy(qenum(QSizePolicy, "Expanding"), qenum(QSizePolicy, "Fixed"))

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        g = QLinearGradient(0, 0, self.width(), self.height())
        g.setColorAt(0.0, QColor("#0a3a7a"))
        g.setColorAt(1.0, QColor("#2a7fd0"))
        p.fillRect(self.rect(), g)
        x = 16
        if not self.icon.isNull():
            self.icon.paint(p, x, 10, 48, 48)
            x += 60
        p.setPen(QColor("#ffffff"))
        f = QFont(self.font())
        f.setPointSizeF(max(8.0, f.pointSizeF() * 1.05))
        p.setFont(f)
        p.drawText(x, 30, "Remote Desktop")
        f2 = QFont(self.font())
        f2.setPointSizeF(max(10.0, f2.pointSizeF() * 1.75))
        f2.setBold(True)
        p.setFont(f2)
        p.drawText(x, 56, "Connection")
        p.end()


class _Bridge(QObject):
    """Moves results from worker threads to the GUI thread."""
    cert_done = pyqtSignal(object, object)        # attempt, CertInfo
    cert_failed = pyqtSignal(object, str)         # attempt, message
    sess_connected = pyqtSignal(object)           # attempt
    sess_finished = pyqtSignal(object, int, object, bool)  # attempt, code, lines, connected
    sess_line = pyqtSignal(object, str)


class Attempt:
    """One press of Connect (it may take several logon tries)."""

    def __init__(self, profile: RdpProfile, username: str, password: Optional[str], remember: bool):
        self.profile = profile
        self.host, self.port = profile.address
        self.username = username
        self.password = password
        self.password_source = "cli" if password is not None else ""
        self.remember = remember
        self.tries = 0
        self.fingerprint = ""
        self.cert_policy = "deny"
        self.session: Optional[Session] = None
        self.dialog: Optional[ConnectingDialog] = None
        self.cancelled = False
        self.connected = False
        self.log: List[str] = []
        self.command = ""
        self.started = time.time()

    @property
    def label(self) -> str:
        return join_address(self.host, self.port)


def _icon_group(title: str, pixmap, inner) -> QGroupBox:
    g = QGroupBox(title)
    row = QHBoxLayout(g)
    ic = QLabel()
    ic.setPixmap(pixmap)
    ic.setAlignment(qenum(Qt, "AlignTop"))
    ic.setFixedWidth(40)
    row.addWidget(ic)
    if isinstance(inner, QWidget):
        row.addWidget(inner, 1)
    else:
        row.addLayout(inner, 1)
    return g


class MainWindow(QMainWindow):
    def __init__(self, cli: Optional[Dict] = None, settings: Optional[Dict] = None):
        super().__init__()
        self.cli = cli or {}
        self.settings = settings if settings is not None else config.load_settings()
        self.master = config.load_master()
        self.passwords = PasswordManager(self, self.settings, self._status)
        self.bridge = _Bridge()
        self.bridge.cert_done.connect(self._on_cert_done)
        self.bridge.cert_failed.connect(self._on_cert_failed)
        self.bridge.sess_connected.connect(self._on_connected)
        self.bridge.sess_finished.connect(self._on_finished)
        self.bridge.sess_line.connect(self._on_line)
        self.attempts: List[Attempt] = []
        self.current_file: Optional[str] = None
        self._sync_guard = False
        self.profile = self._initial_profile()
        self._build_ui()
        self.load_profile(self.profile)
        self.set_options_visible(bool(self.settings.get("show_options")))
        self.tabs.setCurrentIndex(int(self.settings.get("last_tab") or 0))
        self._update_title()

    # ------------------------------------------------------------------ setup
    def _initial_profile(self) -> RdpProfile:
        path = config.default_rdp_path()
        if self.cli.get("file"):
            try:
                prof = rdpfile.load_rdp(self.cli["file"])
                self.current_file = self.cli["file"]
                return self._apply_cli(prof)
            except RdpFileError as e:
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, APP_NAME, str(e)))
        prof = RdpProfile()
        if os.path.isfile(path):
            try:
                prof = rdpfile.load_rdp(path)
            except RdpFileError:
                prof = RdpProfile()
        return self._apply_cli(prof)

    def _apply_cli(self, prof: RdpProfile) -> RdpProfile:
        c = self.cli
        if c.get("host"):
            prof.set_address(join_address(c["host"], c.get("port") or rdpfile.DEFAULT_PORT))
            prof.set("username", c.get("user") or config.recent_username(self.settings, c["host"]), "s")
        elif c.get("port"):
            host, _p = prof.address
            prof.set_address(join_address(host, c["port"]))
        if c.get("user"):
            prof.set("username", c["user"], "s")
        if c.get("fullscreen"):
            prof.set("screen mode id", 2, "i")
        if c.get("width") and c.get("height"):
            prof.set("screen mode id", 1, "i")
            prof.set("desktopwidth", int(c["width"]), "i")
            prof.set("desktopheight", int(c["height"]), "i")
        if c.get("admin"):
            prof.set("administrative session", 1, "i")
        if c.get("multimon"):
            prof.set("use multimon", 1, "i")
        return prof

    def _px(self, name: str, size: int = 32, fallback: str = "SP_MessageBoxInformation"):
        pix = self.style().standardIcon(qenum(QStyle, name)).pixmap(size, size)
        if pix.isNull() and fallback:
            pix = self.style().standardIcon(qenum(QStyle, fallback)).pixmap(size, size)
        return pix

    def _build_ui(self) -> None:
        self.setWindowTitle("Remote Desktop Connection")
        from .about_config import logo_icon
        logo = logo_icon()
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 8)
        root.setSpacing(0)
        self.banner = Banner(logo)
        root.addWidget(self.banner)

        # Shared logon widgets (moved between the compact view and General tab).
        self.computer = QComboBox()
        self.computer.setEditable(True)
        self.computer.setInsertPolicy(qenum(QComboBox, "NoInsert"))
        self.computer.setMinimumWidth(260)
        self.computer.lineEdit().setPlaceholderText("Example: computer.fabrikam.com")
        self.computer.setToolTip("Computer name or address, optionally with :port")
        self.username = QComboBox()
        self.username.setEditable(True)
        self.username.lineEdit().setPlaceholderText("None specified")
        self.username.setToolTip("User name, DOMAIN\\user or user@domain")
        self.cred_note = QLabel("")
        self.cred_note.setWordWrap(True)
        self.cred_note.setOpenExternalLinks(False)
        self.cred_note.linkActivated.connect(self._cred_link)
        self.computer.editTextChanged.connect(self._computer_changed)
        self.computer.activated.connect(lambda _i: self._computer_changed(self.computer.currentText()))

        # Compact view
        self.compact = QWidget()
        cl = QGridLayout(self.compact)
        cl.setContentsMargins(24, 16, 24, 6)
        self.compact_grid = cl
        cl.setColumnStretch(1, 1)
        lbl_c = QLabel("&Computer:")
        lbl_c.setBuddy(self.computer)
        lbl_u = QLabel("&User name:")
        lbl_u.setBuddy(self.username)
        self.compact_labels = (lbl_c, lbl_u)
        root.addWidget(self.compact)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(False)
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.setContentsMargins(10, 10, 10, 0)
        hl.addWidget(self.tabs)
        self.tabs_holder = holder
        root.addWidget(holder, 1)
        self._build_general()
        self._build_display()
        self._build_local()
        self._build_experience()
        self._build_advanced()

        # Bottom buttons
        bottom = QHBoxLayout()
        bottom.setContentsMargins(10, 8, 10, 0)
        self.options_btn = QPushButton("Show &Options")
        self.options_btn.setFlat(True)
        self.options_btn.clicked.connect(lambda: self.set_options_visible(not self.tabs_holder.isVisible()))
        bottom.addWidget(self.options_btn)
        bottom.addStretch(1)
        self.connect_btn = QPushButton("Co&nnect")
        self.connect_btn.setDefault(True)
        self.connect_btn.setAutoDefault(True)
        self.connect_btn.setMinimumWidth(96)
        self.connect_btn.clicked.connect(self.connect_clicked)
        self.help_btn = QPushButton("&Help")
        self.help_btn.setMinimumWidth(80)
        self.help_btn.clicked.connect(self.show_help)
        bottom.addWidget(self.connect_btn)
        bottom.addWidget(self.help_btn)
        root.addLayout(bottom)
        self._build_menus()
        self.statusBar().setSizeGripEnabled(False)
        self._refresh_recent()

    def _place_logon(self, compact: bool) -> None:
        widgets = [self.computer, self.username, self.cred_note] + list(self.compact_labels)
        for w in widgets:
            for lay in (self.compact_grid, self.general_grid):
                lay.removeWidget(w)
        grid = self.compact_grid if compact else self.general_grid
        r = 0 if compact else 1
        grid.addWidget(self.compact_labels[0], r, 0)
        grid.addWidget(self.computer, r, 1)
        grid.addWidget(self.compact_labels[1], r + 1, 0)
        grid.addWidget(self.username, r + 1, 1)
        grid.addWidget(self.cred_note, r + 2, 0, 1, 2)
        for w in widgets:
            w.show()

    def _build_general(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        inner = QWidget()
        g = QGridLayout(inner)
        g.setContentsMargins(0, 0, 0, 0)
        g.addWidget(QLabel("Enter the name of the remote computer."), 0, 0, 1, 2)
        self.general_grid = g
        g.setColumnStretch(1, 1)
        self.allow_save = QCheckBox("Allow me to save credentials")
        self.allow_save.setChecked(bool(self.settings.get("allow_save_credentials", True)))
        self.allow_save.toggled.connect(self._allow_save_toggled)
        g.addWidget(self.allow_save, 4, 0, 1, 2)
        lay.addWidget(_icon_group("Logon settings", self._px("SP_ComputerIcon"), inner))

        inner2 = QWidget()
        l2 = QVBoxLayout(inner2)
        l2.setContentsMargins(0, 0, 0, 0)
        t = QLabel("Save the current connection settings to an RDP file or open a saved connection.")
        t.setWordWrap(True)
        l2.addWidget(t)
        row = QHBoxLayout()
        self.save_btn = QPushButton("&Save")
        self.saveas_btn = QPushButton("Sa&ve As...")
        self.open_btn = QPushButton("Op&en...")
        self.save_btn.clicked.connect(self.save_file)
        self.saveas_btn.clicked.connect(self.save_file_as)
        self.open_btn.clicked.connect(self.open_file_dialog)
        for b in (self.save_btn, self.saveas_btn, self.open_btn):
            row.addWidget(b)
        row.addStretch(1)
        l2.addLayout(row)
        lay.addWidget(_icon_group("Connection settings", self._px("SP_DialogSaveButton"), inner2))
        lay.addStretch(1)
        self.tabs.addTab(tab, "General")

    def _build_display(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        inner = QWidget()
        l1 = QVBoxLayout(inner)
        l1.setContentsMargins(0, 0, 0, 0)
        t = QLabel("Choose the size of your remote desktop. Drag the slider all the way to the "
                   "right to use the full screen.")
        t.setWordWrap(True)
        l1.addWidget(t)
        row = QHBoxLayout()
        row.addWidget(QLabel("Small"))
        self.size_slider = QSlider(qenum(Qt, "Horizontal"))
        self.size_slider.setTickPosition(qenum(QSlider, "TicksBelow"))
        self.size_slider.setPageStep(1)
        self.size_slider.valueChanged.connect(self._slider_changed)
        row.addWidget(self.size_slider, 1)
        row.addWidget(QLabel("Large"))
        l1.addLayout(row)
        self.size_label = QLabel("Full Screen")
        self.size_label.setAlignment(qenum(Qt, "AlignHCenter"))
        l1.addWidget(self.size_label)
        self.multimon = QCheckBox("Use all my monitors for the remote session")
        l1.addWidget(self.multimon)
        self.dynres = QCheckBox("Resize the remote desktop when I resize the window")
        self.smart = QCheckBox("Scale the remote desktop to fit the window (smart sizing)")
        l1.addWidget(self.dynres)
        l1.addWidget(self.smart)
        lay.addWidget(_icon_group("Display configuration", self._px("SP_DesktopIcon"), inner))

        inner2 = QWidget()
        l2 = QVBoxLayout(inner2)
        l2.setContentsMargins(0, 0, 0, 0)
        l2.addWidget(QLabel("Choose the color depth of the remote session."))
        self.color = QComboBox()
        for bpp, text in COLOR_DEPTHS:
            self.color.addItem(text, bpp)
        l2.addWidget(self.color)
        lay.addWidget(_icon_group("Colors", self._px("SP_DriveDVDIcon"), inner2))
        self.conn_bar = QCheckBox("Display the connection bar when I use the full screen")
        lay.addWidget(self.conn_bar)
        lay.addStretch(1)
        self._fill_sizes()
        self.tabs.addTab(tab, "Display")

    def _fill_sizes(self, extra=None) -> None:
        screen = QGuiApplication.primaryScreen()
        sw, sh = (1920, 1200)
        if screen is not None:
            s = screen.size()
            sw, sh = max(s.width(), 1920), max(s.height(), 1200)
        sizes = [r for r in RESOLUTIONS if r[0] <= sw and r[1] <= sh]
        if extra and extra not in sizes:
            sizes.append(extra)
            sizes.sort()
        self.sizes = sizes
        self.size_slider.blockSignals(True)
        self.size_slider.setRange(0, len(sizes))  # last step = Full Screen
        self.size_slider.blockSignals(False)

    def _slider_changed(self, v: int) -> None:
        if v >= len(self.sizes):
            self.size_label.setText("Full Screen")
        else:
            w, h = self.sizes[v]
            self.size_label.setText("%d by %d pixels" % (w, h))
        self.multimon.setEnabled(v >= len(self.sizes))

    def _build_local(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        inner = QWidget()
        l1 = QVBoxLayout(inner)
        l1.setContentsMargins(0, 0, 0, 0)
        l1.addWidget(QLabel("Configure remote audio settings."))
        row = QHBoxLayout()
        self.audio_btn = QPushButton("Se&ttings...")
        self.audio_btn.clicked.connect(self._audio_settings)
        row.addWidget(self.audio_btn)
        row.addStretch(1)
        l1.addLayout(row)
        lay.addWidget(_icon_group("Remote audio", self._px("SP_MediaVolume"), inner))

        inner2 = QWidget()
        l2 = QVBoxLayout(inner2)
        l2.setContentsMargins(0, 0, 0, 0)
        l2.addWidget(QLabel("Apply Windows key combinations:"))
        self.kbd = QComboBox()
        for v, text in KEYBOARD_HOOK:
            self.kbd.addItem(text, v)
        l2.addWidget(self.kbd)
        ex = QLabel("Example: ALT+TAB")
        ex.setEnabled(False)
        l2.addWidget(ex)
        lay.addWidget(_icon_group("Keyboard", self._px("SP_FileDialogDetailedView"), inner2))

        inner3 = QWidget()
        l3 = QVBoxLayout(inner3)
        l3.setContentsMargins(0, 0, 0, 0)
        t = QLabel("Choose the devices and resources that you want to use in your remote session.")
        t.setWordWrap(True)
        l3.addWidget(t)
        row3 = QHBoxLayout()
        self.printers = QCheckBox("&Printers")
        self.clipboard = QCheckBox("Clip&board")
        row3.addWidget(self.printers)
        row3.addWidget(self.clipboard)
        row3.addStretch(1)
        l3.addLayout(row3)
        row4 = QHBoxLayout()
        self.more_btn = QPushButton("&More...")
        self.more_btn.clicked.connect(self._devices)
        row4.addWidget(self.more_btn)
        row4.addStretch(1)
        l3.addLayout(row4)
        lay.addWidget(_icon_group("Local devices and resources", self._px("SP_DriveHDIcon"), inner3))
        lay.addStretch(1)
        self.tabs.addTab(tab, "Local Resources")

    def _build_experience(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        inner = QWidget()
        l1 = QVBoxLayout(inner)
        l1.setContentsMargins(0, 0, 0, 0)
        l1.addWidget(QLabel("Choose your connection speed to optimize performance."))
        self.speed = QComboBox()
        for v, text in CONNECTION_TYPES:
            self.speed.addItem(text, v)
        self.speed.activated.connect(self._speed_changed)
        l1.addWidget(self.speed)
        l1.addWidget(QLabel("Allow the following:"))
        self.exp_boxes = [QCheckBox(t) for t in EXPERIENCE_LABELS]
        for b in self.exp_boxes:
            l1.addWidget(b)
        lay.addWidget(_icon_group("Performance", self._px("SP_BrowserReload"), inner))
        self.reconnect = QCheckBox("&Reconnect if the connection is dropped")
        lay.addWidget(self.reconnect)
        lay.addStretch(1)
        self.tabs.addTab(tab, "Experience")

    def _speed_changed(self, _i=None) -> None:
        ctype = int(self.speed.currentData())
        tmp = RdpProfile()
        tmp.apply_connection_type(ctype)
        for b, on in zip(self.exp_boxes, tmp.experience()):
            b.setChecked(on)
        for b in self.exp_boxes:
            b.setEnabled(ctype != 7)

    def _build_advanced(self) -> None:
        tab = QWidget()
        lay = QVBoxLayout(tab)
        inner = QWidget()
        l1 = QVBoxLayout(inner)
        l1.setContentsMargins(0, 0, 0, 0)
        t = QLabel("Server authentication verifies that you are connecting to the intended remote "
                   "computer. The strength of the verification required to connect is set here.")
        t.setWordWrap(True)
        l1.addWidget(t)
        l1.addWidget(QLabel("If server authentication fails:"))
        self.auth_level = QComboBox()
        for v, text in AUTH_LEVELS:
            self.auth_level.addItem(text, v)
        l1.addWidget(self.auth_level)
        self.nla = QCheckBox("Use Network Level Authentication (NLA) when the computer supports it")
        l1.addWidget(self.nla)
        self.admin = QCheckBox("Connect to the administrative (console) session")
        l1.addWidget(self.admin)
        lay.addWidget(_icon_group("Server authentication", self._px("SP_VistaShield"), inner))

        inner2 = QWidget()
        l2 = QVBoxLayout(inner2)
        l2.setContentsMargins(0, 0, 0, 0)
        t2 = QLabel("Configure settings to connect through Remote Desktop Gateway when I am working remotely.")
        t2.setWordWrap(True)
        l2.addWidget(t2)
        row = QHBoxLayout()
        self.gw_btn = QPushButton("&Settings...")
        self.gw_btn.clicked.connect(self._gateway)
        row.addWidget(self.gw_btn)
        self.gw_label = QLabel("")
        self.gw_label.setEnabled(False)
        row.addWidget(self.gw_label, 1)
        l2.addLayout(row)
        lay.addWidget(_icon_group("Connect from anywhere", self._px("SP_DriveNetIcon"), inner2))
        lay.addStretch(1)
        self.tabs.addTab(tab, "Advanced")

    def _build_menus(self) -> None:
        mb = self.menuBar()
        m = mb.addMenu("&File")
        self.act_open = m.addAction("&Open...")
        self.act_open.setShortcut(QKeySequence("Ctrl+O"))
        self.act_open.triggered.connect(self.open_file_dialog)
        self.recent_menu = m.addMenu("Open &Recent")
        self.act_save = m.addAction("&Save")
        self.act_save.setShortcut(QKeySequence("Ctrl+S"))
        self.act_save.triggered.connect(self.save_file)
        self.act_saveas = m.addAction("Save &As...")
        self.act_saveas.setShortcut(QKeySequence("Ctrl+Shift+S"))
        self.act_saveas.triggered.connect(self.save_file_as)
        m.addSeparator()
        self.act_connect = m.addAction("Co&nnect")
        self.act_connect.setShortcut(QKeySequence("Ctrl+Return"))
        self.act_connect.triggered.connect(self.connect_clicked)
        self.act_log = m.addAction("Last Session &Log...")
        self.act_log.setShortcut(QKeySequence("Ctrl+L"))
        self.act_log.triggered.connect(self.show_last_log)
        m.addSeparator()
        self.act_quit = m.addAction("&Quit")
        self.act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        self.act_quit.triggered.connect(self.close)

        o = mb.addMenu("&Options")
        self.act_show_opts = o.addAction("Show &Options")
        self.act_show_opts.setShortcut(QKeySequence("Alt+O"))
        self.act_show_opts.triggered.connect(lambda: self.set_options_visible(not self.tabs_holder.isVisible()))
        o.addSeparator()
        self.act_passwords = o.addAction("&Passwords...")
        self.act_passwords.triggered.connect(self.password_options)
        self.act_lock = o.addAction("&Lock Password Vault")
        self.act_lock.triggered.connect(self.passwords.lock_vault)
        self.act_certs = o.addAction("Saved &Certificates...")
        self.act_certs.triggered.connect(lambda: exec_(KnownCertsDialog(self)))
        self.act_clear_recent = o.addAction("Clear Recent &Computers")
        self.act_clear_recent.triggered.connect(self.clear_recent)

        h = mb.addMenu("&Help")
        self.act_help = h.addAction("%s &Help" % "Helm")
        self.act_help.setShortcut(QKeySequence("F1"))
        self.act_help.triggered.connect(self.show_help)
        h.addSeparator()
        self.act_about = h.addAction("&About Helm")
        self.act_about.triggered.connect(self.show_about)

    # ------------------------------------------------------------- view state
    def set_options_visible(self, show: bool) -> None:
        self.tabs_holder.setVisible(show)
        self.compact.setVisible(not show)
        self._place_logon(compact=not show)
        self.options_btn.setText("Hide &Options" if show else "Show &Options")
        self.act_show_opts.setText("Hide &Options" if show else "Show &Options")
        self.settings["show_options"] = show
        if show:
            self.tabs.setCurrentIndex(self.tabs.currentIndex())
        self.setMinimumSize(0, 0)
        self.adjustSize()
        self.resize(470 if not show else 500, self.sizeHint().height())

    def _update_title(self) -> None:
        name = os.path.basename(self.current_file) if self.current_file else ""
        self.setWindowTitle("Remote Desktop Connection" + (" - %s" % name if name else ""))

    def _status(self, msg: str) -> None:
        self.statusBar().showMessage(msg, 8000)

    def _refresh_recent(self) -> None:
        text = self.computer.currentText()
        self.computer.blockSignals(True)
        self.computer.clear()
        for r in self.settings.get("recent", []):
            self.computer.addItem(r.get("host", ""))
        self.computer.setEditText(text)
        self.computer.blockSignals(False)
        users = []
        for r in self.settings.get("recent", []):
            u = r.get("username", "")
            if u and u not in users:
                users.append(u)
        cur = self.username.currentText()
        self.username.clear()
        self.username.addItems(users)
        self.username.setEditText(cur)
        self.recent_menu.clear()
        for r in self.settings.get("recent", []):
            a = self.recent_menu.addAction(r.get("host", ""))
            a.triggered.connect(lambda _c=False, h=r.get("host", ""): self._pick_recent(h))
        self.recent_menu.setEnabled(bool(self.settings.get("recent")))

    def _pick_recent(self, host: str) -> None:
        self.computer.setEditText(host)
        self._computer_changed(host)

    @staticmethod
    def _target(text: str) -> str:
        """Key for saved credentials: host, or host:port when not 3389."""
        host, port = rdpfile.split_address(text)
        return join_address(host, port or rdpfile.DEFAULT_PORT) if host else ""

    def _computer_changed(self, text: str) -> None:
        host = self._target(text)
        u = config.recent_username(self.settings, host)
        saved = self.passwords.saved_entry(host) if host else None
        if saved and saved.get("username"):
            u = saved["username"]
        if u:
            self.username.setEditText(u)
        self._update_cred_note()

    def _update_cred_note(self) -> None:
        host = self._target(self.computer.currentText())
        if host and self.passwords.has_saved(host):
            self.cred_note.setText("Saved credentials will be used to connect to this computer. "
                                   "You can <a href='edit'>edit</a> or <a href='delete'>delete</a> "
                                   "these credentials.")
        else:
            self.cred_note.setText("You will be asked for credentials when you connect.")

    def _cred_link(self, which: str) -> None:
        host = self._target(self.computer.currentText())
        if which == "delete":
            if QMessageBox.question(self, "Remote Desktop Connection",
                                    "Delete the saved credentials for %s?" % host) == qenum(QMessageBox, "Yes"):
                self.passwords.forget(host)
        elif which == "edit":
            dlg = CredentialsDialog(self, host, self.username.currentText(),
                                    remember_label=self.passwords.store_label(), remember_checked=True)
            if _accepted(exec_(dlg)):
                user, pw, remember = dlg.values()
                self.username.setEditText(user)
                if remember:
                    self.passwords.save(host, user, pw)
        self._update_cred_note()

    def _allow_save_toggled(self, on: bool) -> None:
        self.settings["allow_save_credentials"] = bool(on)

    # ---------------------------------------------------------- profile <-> UI
    def load_profile(self, p: RdpProfile) -> None:
        self.profile = p
        self.computer.setEditText(p.get_str("full address"))
        self.username.setEditText(p.get_str("username"))
        w, h = p.get_int("desktopwidth", 1920), p.get_int("desktopheight", 1080)
        self._fill_sizes((w, h))
        if p.get_int("screen mode id", 2) == 2:
            self.size_slider.setValue(len(self.sizes))
        else:
            self.size_slider.setValue(self.sizes.index((w, h)) if (w, h) in self.sizes else len(self.sizes) - 1)
        self._slider_changed(self.size_slider.value())
        self.multimon.setChecked(p.get_bool("use multimon"))
        self.dynres.setChecked(p.get_bool("dynamic resolution"))
        self.smart.setChecked(p.get_bool("smart sizing"))
        i = self.color.findData(p.get_int("session bpp", 32))
        self.color.setCurrentIndex(i if i >= 0 else 3)
        self.conn_bar.setChecked(p.get_bool("displayconnectionbar", True))
        self.audiomode = p.get_int("audiomode", 0)
        self.audiocapture = p.get_bool("audiocapturemode")
        i = self.kbd.findData(p.get_int("keyboardhook", 2))
        self.kbd.setCurrentIndex(max(0, i))
        self.printers.setChecked(p.get_bool("redirectprinters"))
        self.clipboard.setChecked(p.get_bool("redirectclipboard", True))
        self.smartcards = p.get_bool("redirectsmartcards")
        self.drives = p.drives()
        i = self.speed.findData(p.get_int("connection type", 7))
        self.speed.setCurrentIndex(i if i >= 0 else 6)
        for b, on in zip(self.exp_boxes, p.experience()):
            b.setChecked(on)
        for b in self.exp_boxes:
            b.setEnabled(p.get_int("connection type", 7) != 7)
        self.reconnect.setChecked(p.get_bool("autoreconnection enabled", True))
        i = self.auth_level.findData(p.get_int("authentication level", 2))
        self.auth_level.setCurrentIndex(i if i >= 0 else 1)
        self.nla.setChecked(p.get_bool("enablecredsspsupport", True))
        self.admin.setChecked(p.get_bool("administrative session"))
        self._update_gw_label()
        self._update_cred_note()

    def profile_from_ui(self) -> RdpProfile:
        p = self.profile.copy()
        p.set_address(self.computer.currentText())
        p.set("username", self.username.currentText().strip(), "s")
        v = self.size_slider.value()
        if v >= len(self.sizes):
            p.set("screen mode id", 2, "i")
            w, h = (self.sizes[-1] if self.sizes else (1920, 1080))
            scr = QGuiApplication.primaryScreen()
            if scr is not None:
                w, h = scr.size().width(), scr.size().height()
        else:
            p.set("screen mode id", 1, "i")
            w, h = self.sizes[v]
        p.set("desktopwidth", w, "i")
        p.set("desktopheight", h, "i")
        p.set("use multimon", 1 if self.multimon.isChecked() else 0, "i")
        p.set("dynamic resolution", 1 if self.dynres.isChecked() else 0, "i")
        p.set("smart sizing", 1 if self.smart.isChecked() else 0, "i")
        p.set("session bpp", int(self.color.currentData()), "i")
        p.set("displayconnectionbar", 1 if self.conn_bar.isChecked() else 0, "i")
        p.set("audiomode", self.audiomode, "i")
        p.set("audiocapturemode", 1 if self.audiocapture else 0, "i")
        p.set("keyboardhook", int(self.kbd.currentData()), "i")
        p.set("redirectprinters", 1 if self.printers.isChecked() else 0, "i")
        p.set("redirectclipboard", 1 if self.clipboard.isChecked() else 0, "i")
        p.set("redirectsmartcards", 1 if self.smartcards else 0, "i")
        p.set_drives(self.drives)
        ctype = int(self.speed.currentData())
        p.set("connection type", ctype, "i")
        p.set("networkautodetect", 1 if ctype == 7 else 0, "i")
        p.set("bandwidthautodetect", 1 if ctype == 7 else 0, "i")
        p.set_experience([b.isChecked() for b in self.exp_boxes])
        p.set("autoreconnection enabled", 1 if self.reconnect.isChecked() else 0, "i")
        p.set("authentication level", int(self.auth_level.currentData()), "i")
        if not self.nla.isChecked() or p.get("enablecredsspsupport") is not None:
            p.set("enablecredsspsupport", 1 if self.nla.isChecked() else 0, "i")
        if self.admin.isChecked() or p.get("administrative session") is not None:
            p.set("administrative session", 1 if self.admin.isChecked() else 0, "i")
        return p

    def _audio_settings(self) -> None:
        dlg = AudioDialog(self, self.audiomode, self.audiocapture)
        if _accepted(exec_(dlg)):
            self.audiomode, self.audiocapture = dlg.values()

    def _devices(self) -> None:
        dlg = DevicesDialog(self, self.smartcards, self.drives)
        if _accepted(exec_(dlg)):
            self.smartcards, self.drives = dlg.values()

    def _gateway(self) -> None:
        p = self.profile_from_ui()
        dlg = GatewayDialog(self, p)
        if _accepted(exec_(dlg)):
            dlg.apply_to(p)
            self.profile = p
            self._update_gw_label()

    def _update_gw_label(self) -> None:
        p = self.profile
        gw = p.get_str("gatewayhostname")
        if gw and p.get_int("gatewayusagemethod", 4) in (1, 2) and p.get_int("gatewayprofileusagemethod", 0) == 1:
            self.gw_label.setText("Gateway: %s" % gw)
        else:
            self.gw_label.setText("No RD Gateway")

    # ------------------------------------------------------------------ files
    def open_file_dialog(self) -> None:
        start = self.settings.get("last_dir") or os.path.expanduser("~")
        path, _ = QFileDialog.getOpenFileName(self, "Open", start, "Remote Desktop Files (*.rdp);;All files (*)")
        if path:
            self.open_file(path)

    def open_file(self, path: str) -> bool:
        try:
            prof = rdpfile.load_rdp(path)
        except RdpFileError as e:
            QMessageBox.warning(self, "Remote Desktop Connection", str(e))
            return False
        self.current_file = path
        self.settings["last_dir"] = os.path.dirname(path)
        self.load_profile(prof)
        self._update_title()
        self._status("Opened %s" % path)
        return True

    def save_file(self) -> None:
        if not self.current_file:
            self._save_to(config.default_rdp_path())
            self._status("Saved the settings as the default connection (%s)." % config.default_rdp_path())
            return
        self._save_to(self.current_file)

    def save_file_as(self) -> None:
        host = rdpfile.split_address(self.computer.currentText())[0] or "Default"
        start = os.path.join(self.settings.get("last_dir") or os.path.expanduser("~"), "%s.rdp" % host)
        path, _ = QFileDialog.getSaveFileName(self, "Save As", start, "Remote Desktop Files (*.rdp)")
        if not path:
            return
        if not path.lower().endswith(".rdp"):
            path += ".rdp"
        if self._save_to(path):
            self.current_file = path
            self.settings["last_dir"] = os.path.dirname(path)
            self._update_title()

    def _save_to(self, path: str) -> bool:
        p = self.profile_from_ui()
        try:
            rdpfile.save_rdp(p, path)
        except OSError as e:
            QMessageBox.warning(self, "Remote Desktop Connection", "Could not save %s: %s" % (path, e))
            return False
        self.profile = p
        self._status("Saved %s" % path)
        return True

    def clear_recent(self) -> None:
        self.settings["recent"] = []
        self._save_settings()
        self._refresh_recent()

    def _save_settings(self) -> None:
        self.settings["last_tab"] = self.tabs.currentIndex()
        try:
            config.save_settings(self.settings)
        except OSError:
            pass

    # ------------------------------------------------------------ connecting
    def connect_clicked(self) -> Optional[Attempt]:
        p = self.profile_from_ui()
        host, port = p.address
        if not host:
            QMessageBox.information(self, "Remote Desktop Connection",
                                    "Please enter the name of the remote computer.")
            self.computer.setFocus()
            return None
        username = p.get_str("username")
        password = self.cli.pop("password", None)
        att = Attempt(p, username, password, remember=False)
        level = p.get_int("authentication level", 2)
        att.cert_policy = "ignore" if level == 0 else "deny"
        self.attempts.append(att)
        att.dialog = ConnectingDialog(self, att.label)
        att.dialog.cancel_btn.clicked.connect(lambda: self.cancel_attempt(att))
        att.dialog.show()
        self.profile = p
        if att.cert_policy == "ignore":
            att.dialog.set_step("Initiating remote connection...")
            QTimer.singleShot(0, lambda: self._credentials_step(att))
        else:
            att.dialog.set_step("Checking the remote computer's certificate...")
            timeout = float(self.master.get("connect_timeout") or 15)

            def work():
                try:
                    info = certcheck.fetch(host, port, timeout=timeout)
                    self.bridge.cert_done.emit(att, info)
                except certcheck.CertCheckError as e:
                    self.bridge.cert_failed.emit(att, str(e))
            threading.Thread(target=work, name="certcheck", daemon=True).start()
        return att

    def cancel_attempt(self, att: Attempt) -> None:
        att.cancelled = True
        if att.session and att.session.running():
            att.session.terminate()
        self._close_dialog(att)
        if att in self.attempts and not (att.session and att.session.running()):
            self.attempts.remove(att)

    def _close_dialog(self, att: Attempt) -> None:
        if att.dialog is not None:
            att.dialog.hide()
            att.dialog.deleteLater()
            att.dialog = None

    def _fail(self, att: Attempt, text: str, details: str = "") -> None:
        self._close_dialog(att)
        if att in self.attempts:
            self.attempts.remove(att)
        box = QMessageBox(self)
        box.setWindowTitle("Remote Desktop Connection")
        box.setIcon(qenum(QMessageBox, "Warning"))
        box.setText(text)
        if details:
            box.setDetailedText(details)
        self.last_error_box = box
        exec_(box)
        self._restore()

    def _on_cert_failed(self, att: Attempt, msg: str) -> None:
        if att.cancelled:
            return
        if msg.startswith("DNS:"):
            from .session import NOT_FOUND_TEXT
            self._fail(att, NOT_FOUND_TEXT.format(host=att.host), msg)
        elif msg.startswith("CONNECT:"):
            from .session import CANT_CONNECT_TEXT
            self._fail(att, CANT_CONNECT_TEXT, "%s:%d - %s" % (att.host, att.port, msg[8:].strip()))
        else:
            self._fail(att, "Remote Desktop could not check the identity of %s.\n\n%s" % (att.label, msg))

    def _on_cert_done(self, att: Attempt, info: certcheck.CertInfo) -> None:
        if att.cancelled:
            return
        state = certcheck.classify(info)
        level = att.profile.get_int("authentication level", 2)
        if state in (certcheck.TRUSTED, certcheck.KNOWN):
            att.fingerprint = info.sha256
        elif state == certcheck.NO_CERT:
            att.fingerprint = ""
            att.cert_policy = "ignore"  # standard RDP security has no certificate
        elif level == 1:
            self._fail(att, "Remote Desktop cannot verify the identity of the remote computer, "
                       "and the connection settings say not to connect in that case.\n\n" +
                       "\n".join(info.problems()), certificate_details(info))
            return
        else:
            old = certcheck.known_fingerprint(info.host, info.port)
            if att.dialog is not None:
                att.dialog.hide()
            dlg = CertificateDialog(self, info, changed=(state == certcheck.CHANGED), old_fp=old)
            self.cert_dialog = dlg
            exec_(dlg)
            self.cert_dialog = None
            if dlg.accept_mode is None or att.cancelled:
                self.cancel_attempt(att)
                return
            if dlg.accept_mode == "always":
                try:
                    certcheck.remember(info)
                except OSError as e:
                    self._status("Could not save the certificate: %s" % e)
            att.fingerprint = info.sha256
            if att.dialog is not None:
                att.dialog.show()
        self._credentials_step(att)

    def _credentials_step(self, att: Attempt, message: str = "") -> None:
        if att.cancelled:
            return
        host = att.label
        prompt_always = att.profile.get_bool("prompt for credentials")
        if not message and att.password is None and not prompt_always and self.passwords.has_saved(host):
            pw, saved_user = self.passwords.get(host)
            if pw is not None:
                att.password = pw
                att.password_source = "saved"
                if not att.username:
                    att.username = saved_user
        if message or att.password is None or not att.username or prompt_always:
            allow = self.allow_save.isChecked()
            label = self.passwords.store_label() if allow else None
            if att.dialog is not None:
                att.dialog.hide()
            dlg = CredentialsDialog(self, att.label, att.username, message=message,
                                    remember_label=label, remember_checked=bool(label and att.remember))
            self.cred_dialog = dlg
            ok = _accepted(exec_(dlg))
            self.cred_dialog = None
            if not ok or att.cancelled:
                self.cancel_attempt(att)
                return
            att.username, att.password, att.remember = dlg.values()
            att.password_source = "typed"
            if att.dialog is not None:
                att.dialog.show()
        self._launch(att)

    def _launch(self, att: Attempt) -> None:
        try:
            client = freerdp.find_freerdp(self.master.get("freerdp", "auto"))
        except freerdp.FreeRdpNotFound as e:
            self._fail(att, str(e))
            return
        att.tries += 1
        att.profile.set("username", att.username, "s")
        creds = freerdp.Credentials(att.username, att.password if att.password is not None else "")
        title = "%s - %s" % (att.label, "Remote Desktop Connection")
        try:
            plan = freerdp.plan(client, att.profile, creds, cert_fingerprint=att.fingerprint,
                                cert_policy=att.cert_policy, title=title,
                                log_level=self.master.get("log_level", "INFO"),
                                extra=self.master.get("extra_args", ""),
                                multimon_ok=True)
        except ValueError as e:
            self._fail(att, str(e))
            return
        att.command = freerdp.display_command(plan)
        att.log = ["# %s %s, FreeRDP %s (%s)" % (APP_NAME, __version__, client.version or "?", client.path),
                   "# " + att.command]
        if att.dialog is not None:
            att.dialog.set_step("Securing remote connection...")
        att.session = Session(plan,
                              on_line=lambda line, a=att: self.bridge.sess_line.emit(a, line),
                              on_connected=lambda a=att: self.bridge.sess_connected.emit(a),
                              on_finished=lambda code, lines, conn, a=att: self.bridge.sess_finished.emit(a, code, list(lines), conn))
        try:
            att.session.start()
        except (OSError, ValueError) as e:
            self._fail(att, "Could not start FreeRDP: %s" % e)
            return
        self.last_attempt = att

    def _on_line(self, att: Attempt, line: str) -> None:
        att.log.append(line)
        if att.dialog is not None and not att.connected:
            if "rdpsnd" in line or "Dynamic Virtual Channel" in line or "framebuffer" in line:
                att.dialog.set_step("Configuring remote session...")
            elif "Password:" in line:
                att.dialog.set_step("Estimating connection quality...")

    def _on_connected(self, att: Attempt) -> None:
        att.connected = True
        self._close_dialog(att)
        host = att.label
        if att.remember and att.password is not None and att.password_source == "typed":
            self.passwords.save(host, att.username, att.password)
        att.password = None  # FreeRDP has it now; nothing keeps it in Helm
        config.add_recent(self.settings, att.label, att.username)
        self._save_settings()
        if not self.current_file:
            try:
                rdpfile.save_rdp(att.profile, config.default_rdp_path())
            except OSError:
                pass
        self._refresh_recent()
        self._update_cred_note()
        self._status("Connected to %s" % att.label)
        if self.settings.get("minimize_on_connect", True) and not getattr(self, "_no_minimize", False):
            self.showMinimized()

    def _on_finished(self, att: Attempt, code: int, lines: List[str], connected: bool) -> None:
        out: Outcome = classify(code, lines, att.host, connected)
        att.outcome = out
        att.log.append("# exit code %d -> %s %s" % (code, out.kind, ",".join(out.errors)))
        self.last_attempt = att
        if att.cancelled or out.kind == "cancelled":
            if att in self.attempts:
                self.attempts.remove(att)
            self._close_dialog(att)
            self._restore()
            return
        if out.kind == "auth" and att.tries < MAX_LOGON_TRIES:
            msg = "The logon attempt failed." if att.password_source != "saved" else \
                "Your saved credentials did not work. The logon attempt failed."
            att.password = None
            att.session = None
            if att.dialog is not None:
                att.dialog.set_step("Waiting for credentials...")
            self._credentials_step(att, message=msg)
            return
        if out.kind == "ok":
            self._close_dialog(att)
            if att in self.attempts:
                self.attempts.remove(att)
            self._status("Disconnected from %s" % att.label)
            self._restore()
            return
        self._fail(att, out.message or "The connection ended.", "\n".join(att.log[-200:]))

    def _restore(self) -> None:
        if not any(a.connected and a.session and a.session.running() for a in self.attempts):
            if self.isMinimized():
                self.showNormal()
                self.raise_()
                self.activateWindow()

    def active_sessions(self) -> List[Attempt]:
        return [a for a in self.attempts if a.session and a.session.running()]

    def show_last_log(self) -> None:
        att = getattr(self, "last_attempt", None)
        text = "\n".join(att.log) if att else "No connection yet."
        exec_(SessionLogDialog(self, "Last Session Log — %s" % APP_NAME, text))

    def password_options(self) -> None:
        ring = self.passwords.keyring()
        dlg = PasswordOptionsDialog(self, self.settings, ring.available, ring.error or "")
        dlg.change_master_btn.clicked.connect(lambda: self.passwords.change_master(dlg.vault_path()))
        if _accepted(exec_(dlg)):
            self.settings["password_backend"] = dlg.selected_backend()
            vp = dlg.vault_path()
            from .secret_store import default_vault_path
            self.settings["vault_file"] = "" if vp == default_vault_path() else vp
            self._save_settings()
            self._update_cred_note()

    # ------------------------------------------------------------------- help
    def show_help(self) -> None:
        from .help_dialogs import HelpDialog
        if getattr(self, "_help", None) is None:
            self._help = HelpDialog(self)
        self._help.show()
        self._help.raise_()

    def show_about(self) -> None:
        from .help_dialogs import AboutDialog
        exec_(AboutDialog(self))

    def closeEvent(self, ev) -> None:
        active = self.active_sessions()
        if active:
            box = QMessageBox(self)
            box.setWindowTitle("Remote Desktop Connection")
            box.setIcon(qenum(QMessageBox, "Question"))
            box.setText("%d remote session(s) are open. Disconnect them?" % len(active))
            disc = box.addButton("Disconnect", qenum(QMessageBox, "AcceptRole"))
            keep = box.addButton("Keep Them Open", qenum(QMessageBox, "DestructiveRole"))
            box.addButton(qenum(QMessageBox, "Cancel"))
            exec_(box)
            if box.clickedButton() is disc:
                for a in active:
                    a.session.terminate()
            elif box.clickedButton() is not keep:
                ev.ignore()
                return
        self._save_settings()
        ev.accept()


def certificate_details(info: certcheck.CertInfo) -> str:
    from .dialogs import certificate_text
    return certificate_text(info)
