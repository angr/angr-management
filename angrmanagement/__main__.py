import sys
import os
import ctypes
import threading
import time
import warnings

def shut_up(*args, **kwargs):
    return
warnings.simplefilter = shut_up


def check_dependencies():

    try:
        import PySide2
    except ImportError:
        sys.stderr.write("Cannot find the PySide2 package. You may install it via pip:\n" +
                         "    pip install pyside2\n")
        return False

    try:
        import qtconsole
    except ImportError:
        sys.stderr.write("Cannot find the qtconsole package. You may install it via pip:\n" +
                         "    pip install qtconsole\n")
        return False

    return True


def set_app_user_model_id():
    # Explicitly call SetCurrentProcessExplicitAppUserModelID() so the taskbar icon is displayed correctly.

    if sys.platform == 'win32':
        winver = sys.getwindowsversion()
        if winver.major >= 5:
            myappid = u'angr-management'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)


def start_management(filepath=None):

    if not check_dependencies():
        sys.exit(1)

    set_app_user_model_id()

    from PySide2.QtWidgets import QApplication, QSplashScreen, QMessageBox
    from PySide2.QtGui import QFontDatabase, QPixmap, QIcon
    from PySide2.QtCore import Qt

    from .config import FONT_LOCATION, IMG_LOCATION

    app = QApplication(sys.argv)
    app.setApplicationDisplayName("angr management")
    app.setApplicationName("angr management")

    # URL scheme
    from .logic.url_scheme import AngrUrlScheme
    scheme = AngrUrlScheme()
    registered, _ = scheme.is_url_scheme_registered()
    if not registered:
        btn = QMessageBox.question(None, "Setting up angr URL scheme",
                "angr URL scheme allows \"deep linking\" from browsers and other applications by registering the "
                "angr:// protocol to the current user. Do you want to register it? You may unregister at any "
                "time in Preferences.",
                defaultButton=QMessageBox.Yes)
        if btn == QMessageBox.Yes:
            try:
                AngrUrlScheme().register_url_scheme()
            except (ValueError, FileNotFoundError) as ex:
                QMessageBox.error(None, "Error in registering angr URL scheme",
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

    GlobalInfo.gui_thread = threading.get_ident()

    # apply the CSS
    app.setStyleSheet(CSS.global_css())

    # connect to daemon (if there is one)
    if not daemon_exists():
        print("Starting a new daemon.")
        run_daemon_process()
        time.sleep(0.2)
    print("Connecting to an existing angr management daemon.")
    GlobalInfo.daemon_conn = daemon_conn(service=ClientService)

    from rpyc import BgServingThread
    th = BgServingThread(GlobalInfo.daemon_conn)

    file_to_open = filepath if filepath else sys.argv[1] if len(sys.argv) > 1 else None
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
    parser.add_argument("-d", "--daemon", action='store_true', help="start the daemon to handle angr:// URLs.")
    parser.add_argument("-u", "--url", type=str, help="handle angr:// URLs. the daemon must be running.")
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
        start_management(args.binary)

if __name__ == '__main__':
    main()
