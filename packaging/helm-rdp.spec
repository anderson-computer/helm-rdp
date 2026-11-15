%global debug_package %{nil}

Name:           helm-rdp
Version:        1.0.0
Release:        1%{?dist}
Summary:        Remote Desktop Connection (mstsc-style) RDP client for Rocky Linux 9 and 10
License:        MIT
URL:            https://github.com/mike0615/helm-rdp
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3
BuildRequires:  desktop-file-utils
# Unit tests in %%check: vault (cryptography), keychain detection (gi + libsecret).
BuildRequires:  python3-cryptography
BuildRequires:  python3-gobject-base
BuildRequires:  libsecret

Requires:       python3
# Session engine: FreeRDP from AppStream (EL9: 2.11, EL10: 3.x). No EPEL needed.
Requires:       freerdp
# stdbuf, so FreeRDP's log is line-buffered (BaseOS, always installed).
Requires:       coreutils
# AES-256-GCM + scrypt for the encrypted password vault and certificate
# parsing (BaseOS).
Requires:       python3-cryptography
# System keychain for saved passwords (Secret Service through libsecret).
Requires:       python3-gobject-base
Requires:       libsecret
Recommends:     shared-mime-info

# Qt bindings (AppStream):
#   EL9  -> PyQt5 (python3-qt5-base)
#   EL10 -> PyQt6 (python3-pyqt6-base); EL10 has no PyQt5 in AppStream.
%if 0%{?rhel} >= 10
Requires:       python3-pyqt6-base
Recommends:     qt6-qtsvg
Recommends:     qt6-qtwayland
%else
Requires:       python3-qt5-base
Recommends:     qt5-qtsvg
Recommends:     qt5-qtwayland
%endif

%description
Helm Remote Desktop is an RDP client for Rocky Linux 9 and 10 that looks and
works like the Windows Remote Desktop Connection client (mstsc).

A compact Computer / User name window with Show Options for the General,
Display, Local Resources, Experience and Advanced tabs; .rdp files open and
save in the mstsc format; recent computers; certificate warnings in a
dialog with the SHA-256 fingerprint ("Don't ask me again" pins it);
credentials asked for when missing and optionally saved in the system
keychain or an encrypted vault. Sessions run in FreeRDP from AppStream; the
password reaches FreeRDP through a pipe, never the command line.

Other programs can start a connection with
  helm-rdp --host H --user U --port P --password-fd N
(the same hand-off Skiff, Sonar and Porthole use).

%prep
%setup -q -n %{name}-%{version}
find . -name '__pycache__' -prune -exec rm -rf {} +
find . -name '*.py[co]' -delete

%build
# pure Python

%install
rm -rf %{buildroot}
install -d %{buildroot}/opt/helm-rdp
cp -a helm_rdp %{buildroot}/opt/helm-rdp/
# Ship byte-code so nothing is written under /opt/helm-rdp at run time.
python3 -m compileall -q -s %{buildroot} -p / %{buildroot}/opt/helm-rdp/helm_rdp
python3 -O -m compileall -q -s %{buildroot} -p / %{buildroot}/opt/helm-rdp/helm_rdp
install -d %{buildroot}%{_bindir}
install -m 0755 bin/helm-rdp %{buildroot}%{_bindir}/helm-rdp
install -d %{buildroot}%{_sysconfdir}/helm-rdp
install -m 0644 packaging/helm-rdp.conf %{buildroot}%{_sysconfdir}/helm-rdp/helm-rdp.conf
install -d %{buildroot}%{_datadir}/applications
install -m 0644 packaging/helm-rdp.desktop %{buildroot}%{_datadir}/applications/helm-rdp.desktop
install -d %{buildroot}%{_datadir}/mime/packages
install -m 0644 packaging/helm-rdp-mime.xml %{buildroot}%{_datadir}/mime/packages/helm-rdp.xml
install -d %{buildroot}%{_datadir}/icons/hicolor/scalable/apps %{buildroot}%{_datadir}/icons/hicolor/256x256/apps
install -m 0644 helm_rdp/icons/helm-rdp.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/helm-rdp.svg
install -m 0644 helm_rdp/icons/helm-rdp.png %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/helm-rdp.png
install -d %{buildroot}%{_datadir}/pixmaps
install -m 0644 helm_rdp/icons/helm-rdp.png %{buildroot}%{_datadir}/pixmaps/helm-rdp.png

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/helm-rdp.desktop
# Network tests use 127.0.0.1 only (fake RDP server, fake FreeRDP).
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -t . -v
find . -name '__pycache__' -prune -exec rm -rf {} +

%post
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database -q %{_datadir}/applications || true
fi
if [ -x /usr/bin/update-mime-database ]; then
    update-mime-database %{_datadir}/mime >/dev/null 2>&1 || true
fi
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -q %{_datadir}/icons/hicolor 2>/dev/null || true
fi

%postun
if [ -x /usr/bin/update-desktop-database ]; then
    update-desktop-database -q %{_datadir}/applications || true
fi
if [ -x /usr/bin/update-mime-database ]; then
    update-mime-database %{_datadir}/mime >/dev/null 2>&1 || true
fi
if [ -x /usr/bin/gtk-update-icon-cache ]; then
    gtk-update-icon-cache -q %{_datadir}/icons/hicolor 2>/dev/null || true
fi

%files
%license LICENSE
%doc README.md HELP.md
%dir %{_sysconfdir}/helm-rdp
%config(noreplace) %{_sysconfdir}/helm-rdp/helm-rdp.conf
/opt/helm-rdp/
%{_bindir}/helm-rdp
%{_datadir}/applications/helm-rdp.desktop
%{_datadir}/mime/packages/helm-rdp.xml
%{_datadir}/icons/hicolor/scalable/apps/helm-rdp.svg
%{_datadir}/icons/hicolor/256x256/apps/helm-rdp.png
%{_datadir}/pixmaps/helm-rdp.png

%changelog
* Sun Nov 15 2026 Mike Anderson <mike@andersoncomputer.us> - 1.0.0-1
- Initial release for Rocky Linux 9 (PyQt5, FreeRDP 2.11) and 10 (PyQt6, FreeRDP 3)
- mstsc-style window: Computer / User name, Show Options with General,
  Display, Local Resources, Experience and Advanced tabs
- Open / Save / Save As .rdp files (mstsc format, UTF-16), Default.rdp,
  recent computers
- Certificate check before connecting; warning dialog with SHA-256
  fingerprint, "Don't ask me again" pinning, changed-certificate warning
- Credentials prompt for a missing user name or password, three logon tries,
  Remember me in the system keychain or encrypted vault
- Password passed to FreeRDP through a pipe (/args-from:fd on FreeRDP 3,
  /from-stdin on FreeRDP 2), never argv or environment
- CLI: --host --user --port --password-fd, .rdp file, mstsc-style /v: /f /admin
- Help (F1), About page, master configuration /etc/helm-rdp/helm-rdp.conf
