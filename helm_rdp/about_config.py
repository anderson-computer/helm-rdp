"""Fixed content for Help > About Helm."""

from __future__ import annotations

import os

from . import APP_NAME as _APP_NAME
from . import __version__

LOGO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "helm-rdp.svg")

APP_NAME = _APP_NAME
VERSION = __version__
TAGLINE = "Remote Desktop Connection (RDP) client for Rocky Linux 9 and 10"
AUTHOR = "Mike Anderson"
COPYRIGHT = "Copyright (c) 2026 Mike Anderson"
LINKS = [
    ("Project page", "https://github.com/mike0615/helm-rdp"),
    ("www.andersoncomputer.net", "https://www.andersoncomputer.net"),
]

LICENSE_NOTICE = (
    "Helm Remote Desktop is free software, released under the MIT License. You may "
    "use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies "
    "of it, provided the copyright notice and permission notice are included in "
    "all copies or substantial portions of the software.\n\n"
    "Helm Remote Desktop is provided \"as is\", without warranty of any kind, express "
    "or implied, including but not limited to the warranties of merchantability, "
    "fitness for a particular purpose and noninfringement. See the MIT License "
    "for more details."
)

LOGO_PNG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "helm-rdp.png")


def logo_icon():
    """The logo as a QIcon: the SVG when Qt's SVG plugin is installed
    (qt5-qtsvg / qt6-qtsvg, a weak dependency), otherwise the PNG."""
    from .qtcompat import QIcon, QtGui
    fmts = [bytes(f).decode().lower() for f in QtGui.QImageReader.supportedImageFormats()]
    path = LOGO_FILE if "svg" in fmts and os.path.isfile(LOGO_FILE) else LOGO_PNG
    return QIcon(path) if os.path.isfile(path) else QIcon()
