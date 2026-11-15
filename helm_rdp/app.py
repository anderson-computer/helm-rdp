"""Helm Remote Desktop entry point."""

from __future__ import annotations

import os
import sys

from . import APP_ID, APP_NAME, __version__


def main(argv=None) -> int:
    argv = list(sys.argv if argv is None else argv)
    from .cli import parse_cli
    qt_argv, opts = parse_cli(argv)
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    from .qtcompat import QApplication, QIcon, QTimer, QtWidgets, exec_
    from .about_config import logo_icon

    app = QApplication(qt_argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setDesktopFileName(APP_ID)
    app.setQuitOnLastWindowClosed(True)
    if "Fusion" in QtWidgets.QStyleFactory.keys():
        app.setStyle("Fusion")
    icon = logo_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)

    from .main_window import MainWindow

    win = MainWindow(cli=opts)
    win.show()
    if opts.get("connect"):
        QTimer.singleShot(150, win.connect_clicked)
    return exec_(app)


if __name__ == "__main__":
    sys.exit(main())
