import sys
import os
import ctypes
import threading
import time
import warnings

def shut_up(*args, **kwargs):
    return
warnings.simplefilter = shut_up


BUGGY_PYSIDE2_VERSIONS = [
    "5.12.1",  # https://github.com/angr/angr-management/issues/59
    "5.14.2",  # Tiffany reported. Verified. Probably caused by
               # https://code.qt.io/cgit/pyside/pyside-setup.git/commit/?h=5.14&id=52299827c64cccc1456f9050fdf3dd8596df3e6f
    "5.14.2.1",  # deadlocks sometimes, although better than 5.14.2
]

def check_dependencies():

    missing_dep = False

    try:
        import PySide2
    except ImportError:
        PySide2 = None
        sys.stderr.write("Cannot find the PySide2 package. You may install it via pip:\n" +
                         "    pip install pyside2\n")
        missing_dep = True

    # version check
    if PySide2 is not None and PySide2.__version__ in BUGGY_PYSIDE2_VERSIONS:
        sys.stderr.write("Your installed version of PySide2 is known to have bugs that may lead to angr management "
                         "crashing. Please switch to other versions.\n"
                         "A known good version of PySide2 is 5.14.1. You may install it via pip:\n"
                         "    pip install -U pyside2==5.14.1\n")
        sys.stderr.write("Bad PySide2 versions include: %s" % ", ".join(BUGGY_PYSIDE2_VERSIONS))
        missing_dep = True

    try:
        import qtconsole
    except ImportError:
        sys.stderr.write("Cannot find the qtconsole package. You may install it via pip:\n" +
                         "    pip install qtconsole\n")
        missing_dep = True

    try:
        import sqlalchemy
    except ImportError:
        sys.stderr.write("Cannot find the sqlalchemy package. You may install it via pip:\n" +
                         "    pip install sqlalchemy\n")
        missing_dep = True

    try:
        import pyqodeng.core
    except ImportError:
        sys.stderr.write("Cannot find the pyqodeng.core package. You may install it via pip:\n" +
                         "    pip install pyqodeng.core\n")
        missing_dep = True

    return not missing_dep


def set_app_user_model_id():
    # Explicitly call SetCurrentProcessExplicitAppUserModelID() so the taskbar icon is displayed correctly.

    if sys.platform == 'win32':
        winver = sys.getwindowsversion()
        if winver.major >= 5:
            myappid = u'angr-management'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)


def start_management(filepath=None, use_daemon=False):

    if not check_dependencies():
        sys.exit(1)

    set_app_user_model_id()

    from PySide2.QtWidgets import QApplication, QSplashScreen, QMessageBox
    from PySide2.QtGui import QFontDatabase, QPixmap, QIcon
    from PySide2.QtCore import Qt

    from .config import FONT_LOCATION, IMG_LOCATION, Conf

    app = QApplication(sys.argv)
    app.setApplicationDisplayName("angr management")
    app.setApplicationName("angr management")

    # URL scheme
    from .logic.url_scheme import AngrUrlScheme
    scheme = AngrUrlScheme()
    registered, _ = scheme.is_url_scheme_registered()
    supported = scheme.is_url_scheme_supported()
    if not registered and supported:
        btn = QMessageBox.question(None, "Setting up angr URL scheme",
                "angr URL scheme allows \"deep linking\" from browsers and other applications by registering the "
                "angr:// protocol to the current user. Do you want to register it? You may unregister at any "
                "time in Preferences.",
                defaultButton=QMessageBox.Yes)
        if btn == QMessageBox.Yes:
            try:
                AngrUrlScheme().register_url_scheme()
            except (ValueError, FileNotFoundError) as ex:
                QMessageBox.warning(None, "Error in registering angr URL scheme",
                        "Failed to register the angr URL scheme.\n"
                        "The following exception occurred:\n"
                        + str(ex))

    # Make + display splash screen
    splashscreen_location = os.path.join(IMG_LOCATION, 'angr-splash.png')
    splash_pixmap = QPixmap(splashscreen_location)
    splash = QSplashScreen(splash_pixmap, Qt.WindowStaysOnTopHint)
    icon_location = os.path.join(IMG_LOCATION, 'angr.png')
    splash.setWindowIcon(QIcon(icon_location))
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setEnabled(False)
    splash.show()
    time.sleep(0.05)
    app.processEvents()

    from .logic import GlobalInfo
    from .ui.css import CSS
    from .ui.main_window import MainWindow
    from .daemon import daemon_exists, run_daemon_process, daemon_conn
    from .daemon.client import ClientService

    # Load fonts
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "SourceCodePro-Regular.ttf"))
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "DejaVuSansMono.ttf"))

    # Initialize font-related configuration
    Conf.init_font_config()
    # Set global font
    app.setFont(Conf.ui_default_font)

    GlobalInfo.gui_thread = threading.get_ident()

    # apply the CSS
    app.setStyleSheet(CSS.global_css())

    if use_daemon:
        # connect to daemon (if there is one)
        if not daemon_exists():
            print("[+] Starting a new daemon.")
            run_daemon_process()
            time.sleep(0.2)
        else:
            print("[+] Connecting to an existing angr management daemon.")

        while True:
            try:
                GlobalInfo.daemon_conn = daemon_conn(service=ClientService)
            except ConnectionRefusedError:
                print("[-] Connection failed... try again.")
                time.sleep(0.4)
                continue
            print("[+] Connected to daemon.")
            break

        from rpyc import BgServingThread
        th = BgServingThread(GlobalInfo.daemon_conn)

    file_to_open = filepath if filepath else None
    main_window = MainWindow()
    splash.finish(main_window)

    if file_to_open is not None:
        main_window.load_file(file_to_open)

    app.exec_()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="angr management")
    parser.add_argument("-s", "--script", type=str, help="run a python script in the (commandline) angr environment")
    parser.add_argument("-i", "--interactive", action='store_true', help="interactive (ipython) mode")
    parser.add_argument("-n", "--no-gui", action='store_true', help="run in headless mode")
    parser.add_argument('-d', "--with-daemon", action='store_true', help="use angr with the daemon. this allows angr "
                                                                         "to handle angr:// URLs. it will "
                                                                         "automatically start a daemon if there isn't "
                                                                         "already one running.")
    parser.add_argument("-D", "--daemon", action='store_true', help="start a daemon to handle angr:// URLs.")
    parser.add_argument("-u", "--url", type=str, help="(internal) handle angr:// URLs. the daemon must be running.")
    parser.add_argument("binary", nargs="?", help="the binary to open (for the GUI)")

    args = parser.parse_args()

    if args.daemon:
        from .daemon import start_daemon
        start_daemon()
        return
    elif args.url:
        from .daemon import daemon_exists, handle_url, run_daemon_process, daemon_conn
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
        script_globals = runpy.run_path(args.script)
    if args.interactive:
        if args.script:
            print("Your script's globals() dict is available in the `script_globals` variable.")
        import IPython
        IPython.embed(banner1="")
    if not args.no_gui:
        start_management(args.binary, use_daemon=args.with_daemon)

if __name__ == '__main__':
    main()
