# pylint:disable=import-outside-toplevel,unused-import,no-member
import asyncio
import sys
import os
import ctypes
import threading
import time
import warnings
import platform
import signal

def shut_up(*args, **kwargs):
    return
warnings.simplefilter = shut_up


BUGGY_PYSIDE2_VERSIONS = [
    "5.12.1",  # https://github.com/angr/angr-management/issues/59
    "5.14.2",  # Tiffany reported. Verified. Probably caused by
               # https://code.qt.io/cgit/pyside/pyside-setup.git/commit/?h=5.14&id=52299827c64cccc1456f9050fdf3dd8596df3e6f
    "5.14.2.1",  # deadlocks sometimes, although better than 5.14.2
]


def check_dependencies_qt():

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

    return not missing_dep


def check_dependencies():

    missing_dep = False

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

    try:
        import xdg
    except ImportError:
        sys.stderr.write("Cannot find the xdg package. You may install it via pip:\n" +
                         "    pip install pyxdg\n")
        missing_dep = True

    try:
        import requests
    except ImportError:
        sys.stderr.write("Cannot find the requests package. You may install it via pip:\n" +
                         "    pip install requests\n")
        missing_dep = True

    return not missing_dep


def set_app_user_model_id():
    # Explicitly call SetCurrentProcessExplicitAppUserModelID() so the taskbar icon is displayed correctly.

    if sys.platform == 'win32':
        winver = sys.getwindowsversion()
        if winver.major >= 5:
            myappid = u'angr-management'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)


def set_windows_event_loop_policy():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def macos_bigsur_wants_layer():
    # workaround for https://bugreports.qt.io/browse/QTBUG-87014
    # this is because the latest PySide2 (5.15.2) does not include this fix
    v, _, _ = platform.mac_ver()
    vs = v.split(".")
    if len(vs) >= 2:
        major, minor = list(map(int, vs[:2]))
    else:
        return
    if major >= 11 or major == 10 and minor == 16:
        os.environ['QT_MAC_WANTS_LAYER'] = '1'


def start_management(filepath=None, use_daemon=None, profiling=False):

    if sys.platform == "darwin":
        macos_bigsur_wants_layer()

    if not check_dependencies_qt():
        # it's likely that other dependencies are also missing. check them here before exiting.
        check_dependencies()
        sys.exit(1)

    set_app_user_model_id()
    set_windows_event_loop_policy()

    from PySide2.QtWidgets import QApplication, QSplashScreen, QMessageBox
    from PySide2.QtGui import QFontDatabase, QPixmap, QIcon
    from PySide2.QtCore import Qt, QCoreApplication

    from .config import FONT_LOCATION, IMG_LOCATION, Conf

    # Enable High-DPI support
    # https://stackoverflow.com/questions/35714837/how-to-get-sharp-ui-on-high-dpi-with-qt-5-6
    if ("QT_DEVICE_PIXEL_RATIO" not in os.environ
        and "QT_AUTO_SCREEN_SCALE_FACTOR" not in os.environ
        and "QT_SCALE_FACTOR" not in os.environ
        and "QT_SCREEN_SCALE_FACTORS" not in os.environ
        ):
        QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    # No more rounding
    # https://github.com/pyqtgraph/pyqtgraph/issues/756
    # https://lists.qt-project.org/pipermail/development/2019-September/037434.html
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    # Use highDPI pixmaps
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)

    app = QApplication(sys.argv)
    app.setApplicationDisplayName("angr management")
    app.setApplicationName("angr management")
    icon_location = os.path.join(IMG_LOCATION, 'angr.png')
    QApplication.setWindowIcon(QIcon(icon_location))

    # try to import the initial configuration for the install
    Conf.attempt_importing_initial_config()

    # Make + display splash screen
    splashscreen_location = os.path.join(IMG_LOCATION, 'angr-splash.png')
    splash_pixmap = QPixmap(splashscreen_location)
    splash = QSplashScreen(splash_pixmap, Qt.WindowStaysOnTopHint)
    icon_location = os.path.join(IMG_LOCATION, 'angr.png')
    splash.setWindowIcon(QIcon(icon_location))
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setEnabled(False)
    splash.show()
    for _ in range(5):
        time.sleep(0.01)
        app.processEvents()

    if not check_dependencies():
        sys.exit(1)

    from .ui.css import refresh_theme  # import .ui after shwing the splash screen since it's going to take time

    refresh_theme()

    import angr

    angr.loggers.profiling_enabled = True if profiling else False

    from .logic import GlobalInfo
    from .ui.main_window import MainWindow

    # Load fonts
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "SourceCodePro-Regular.ttf"))
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "DejaVuSansMono.ttf"))

    # Initialize font-related configuration
    Conf.init_font_config()
    # Set global font
    app.setFont(Conf.ui_default_font)

    GlobalInfo.gui_thread = threading.get_ident()

    file_to_open = filepath if filepath else None
    main_window = MainWindow(app=app, use_daemon=use_daemon)
    splash.finish(main_window)

    if file_to_open is not None:
        main_window.load_file(file_to_open)

    app.exec_()


def main():
    import argparse
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    parser = argparse.ArgumentParser(description="angr management")
    parser.add_argument("-s", "--script", type=str, help="run a python script in the (commandline) angr environment")
    parser.add_argument("-i", "--interactive", action='store_true', help="interactive (ipython) mode")
    parser.add_argument("-n", "--no-gui", action='store_true', help="run in headless mode")
    parser.add_argument('-d', "--with-daemon", action='store_true', help="use angr with the daemon. this allows angr "
                                                                         "to handle angr:// URLs. it will "
                                                                         "automatically start a daemon if there isn't "
                                                                         "already one running.")
    parser.add_argument("-D", "--daemon", action='store_true', help="start a daemon to handle angr:// URLs.")
    parser.add_argument("-u", "--url", type=str, nargs='?', help="(internal) handle angr:// URLs. "
                                                                 "the daemon must be running.")
    parser.add_argument("-p", "--profiling", action='store_true', help="display profiling log messages.")
    parser.add_argument('-R', '--autoreload', action='store_true', help="Reload all python modules on each job start.")
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
        start_management(args.binary,
                         use_daemon=True if args.with_daemon else None,
                         profiling=True if args.profiling else None)


if __name__ == '__main__':
    main()
