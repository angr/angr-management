# pylint:disable=import-outside-toplevel,unused-import,no-member
import asyncio
import ctypes
import multiprocessing
import os
import signal
import sys
import threading
import time
import warnings
from typing import Optional

from . import __version__

if sys.platform.startswith("darwin"):
    from Foundation import NSBundle  # pylint: disable=import-error


def shut_up(*args, **kwargs):  # pylint:disable=unused-argument
    return


warnings.simplefilter = shut_up


name: str = "angr management"


def set_app_user_model_id():
    # Explicitly call SetCurrentProcessExplicitAppUserModelID() so the taskbar icon is displayed correctly.

    if sys.platform == "win32":
        winver = sys.getwindowsversion()
        if winver.major >= 5:
            myappid = name.replace(" ", "-")
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)


def set_windows_event_loop_policy():
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def start_management(filepath=None, use_daemon=None, profiling=False):
    set_app_user_model_id()
    set_windows_event_loop_policy()

    from PySide6.QtCore import QMargins, QRectF, Qt
    from PySide6.QtGui import QCursor, QFontDatabase, QGuiApplication, QIcon, QPixmap
    from PySide6.QtWidgets import QApplication, QSplashScreen

    from .config import FONT_LOCATION, IMG_LOCATION, Conf

    class SplashScreen(QSplashScreen):
        """
        angr-management splash screen, showing version, a progress bar, and progress status message.

        Note: Progress message is distinct from the one provided by QSplashScreen::showMessage.
        """

        _progress: float = 0.0
        _progress_message: str = ""

        def setProgress(self, progress: float, progress_message: Optional[str] = None):
            self._progress = progress
            if self._progress_message is not None:
                self._progress_message = progress_message
            self.repaint()

        def drawContents(self, painter):
            super().drawContents(painter)
            contentsRect = self.contentsRect()

            # Draw progress bar
            pbar_height = 3
            pbar_width = contentsRect.width() * max(0.0, min(self._progress, 1.0))
            painter.setPen(Qt.transparent)
            painter.setBrush(Qt.white)
            painter.drawRect(QRectF(0, contentsRect.height() - pbar_height, pbar_width, pbar_height))

            # Draw version and status text
            pad = 6
            r = contentsRect.marginsRemoved(QMargins(pad, pad, pad, pad + pbar_height))
            painter.setPen(Qt.white)
            painter.drawText(r, Qt.AlignTop | Qt.AlignRight, __version__)
            painter.drawText(r, Qt.AlignBottom | Qt.AlignLeft, self._progress_message)

    # Fix app title on macOS
    if sys.platform.startswith("darwin"):
        try:
            bundle = NSBundle.mainBundle()
            info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
            info["CFBundleName"] = name
        except Exception as e:  # pylint: disable=broad-except
            # This happens before logging is setup so use stderr
            print(f"Failed to set App name! {type(e).__name__}: {e}", file=sys.stderr)

    app = QApplication(sys.argv)
    app.setApplicationDisplayName(name)
    app.setApplicationName(name)
    icon_location = os.path.join(IMG_LOCATION, "angr.png")
    QApplication.setWindowIcon(QIcon(icon_location))

    # try to import the initial configuration for the install
    Conf.attempt_importing_initial_config()

    # Make + display splash screen
    splashscreen_location = os.path.join(IMG_LOCATION, "angr-splash.png")
    splash_pixmap = QPixmap(splashscreen_location)
    current_screen = QGuiApplication.screenAt(QCursor.pos())
    splash = SplashScreen(current_screen, splash_pixmap, Qt.WindowStaysOnTopHint)

    icon_location = os.path.join(IMG_LOCATION, "angr.png")
    splash.setWindowIcon(QIcon(icon_location))
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setEnabled(False)
    splash.show()
    for _ in range(5):
        time.sleep(0.01)
        app.processEvents()

    splash.setProgress(0.1, "Importing modules")
    import angr

    from .logic import GlobalInfo
    from .ui.awesome_tooltip_event_filter import QAwesomeTooltipEventFilter
    from .ui.css import refresh_theme  # import .ui after showing the splash screen since it's going to take time
    from .ui.main_window import MainWindow

    angr.loggers.profiling_enabled = bool(profiling)

    splash.setProgress(0.5, "Configuring theme")
    refresh_theme()

    # Load fonts, initialize font-related configuration
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "SourceCodePro-Regular.ttf"))
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "DejaVuSansMono.ttf"))
    Conf.init_font_config()
    Conf.connect("ui_default_font", app.setFont, True)

    # install the global tooltip filter
    app.installEventFilter(QAwesomeTooltipEventFilter(app))

    splash.setProgress(0.9, "Initializing main window")
    GlobalInfo.gui_thread = threading.get_ident()
    file_to_open = filepath if filepath else None
    main_window = MainWindow(app=app, use_daemon=use_daemon)
    splash.setProgress(1.0, "")
    splash.finish(main_window)

    if file_to_open is not None:
        main_window.load_file(file_to_open)

    main_window.initialized = True
    main_window.workspace.view_manager.main_window_initialized()

    app.exec_()


def main():
    import argparse

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    prog: str = name.replace(" ", "-")
    parser = argparse.ArgumentParser(prog=prog, description=name)
    parser.add_argument("-v", "--version", action="version", version=f"{prog} {__version__}")
    parser.add_argument("-s", "--script", type=str, help="run a python script in the (commandline) angr environment")
    parser.add_argument("-i", "--interactive", action="store_true", help="interactive (ipython) mode")
    parser.add_argument("-n", "--no-gui", action="store_true", help="run in headless mode")
    parser.add_argument(
        "-d",
        "--with-daemon",
        action="store_true",
        help="use angr with the daemon. this allows angr "
        "to handle angr:// URLs. it will "
        "automatically start a daemon if there isn't "
        "already one running.",
    )
    parser.add_argument("-D", "--daemon", action="store_true", help="start a daemon to handle angr:// URLs.")
    parser.add_argument(
        "-u", "--url", type=str, nargs="?", help="(internal) handle angr:// URLs. " "the daemon must be running."
    )
    parser.add_argument("-p", "--profiling", action="store_true", help="display profiling log messages.")
    parser.add_argument("-R", "--autoreload", action="store_true", help="Reload all python modules on each job start.")
    parser.add_argument("binary", nargs="?", help="the binary to open (for the GUI)")

    args = parser.parse_args()

    if args.autoreload:
        from .logic import GlobalInfo

        GlobalInfo.autoreload = True

    if args.daemon:
        from .daemon import start_daemon

        start_daemon()
        return
    elif args.url:
        from .daemon import daemon_conn, daemon_exists, handle_url, run_daemon_process

        if not daemon_exists():
            run_daemon_process()
            time.sleep(1)

        # initialize plugins
        from .plugins import PluginManager

        PluginManager(None).discover_and_initialize_plugins()

        action = handle_url(args.url, act=False)
        action.act(daemon_conn())
        return
    if args.script:
        import runpy

        runpy.run_path(args.script)  # pylint:disable=unused-variable
    if args.interactive:
        if args.script:
            print("Your script's globals() dict is available in the `script_globals` variable.")
        import IPython

        IPython.embed(banner1="")
    if not args.no_gui:
        start_management(
            args.binary, use_daemon=True if args.with_daemon else None, profiling=True if args.profiling else None
        )


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
