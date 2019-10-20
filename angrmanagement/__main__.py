import sys
import os
import ctypes
import threading


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


def main(filepath=None):

    if not check_dependencies():
        sys.exit(1)

    set_app_user_model_id()

    from PySide2.QtWidgets import QApplication, QSplashScreen
    from PySide2.QtGui import QFontDatabase, QPixmap, QIcon
    from PySide2.QtCore import Qt

    from .config import FONT_LOCATION, IMG_LOCATION

    app = QApplication(sys.argv)

    # Make + display splash screen
    splashscreen_location = os.path.join(IMG_LOCATION, 'angr-splash.png')
    splash_pixmap = QPixmap(splashscreen_location)
    splash = QSplashScreen(splash_pixmap, Qt.WindowStaysOnTopHint)
    icon_location = os.path.join(IMG_LOCATION, 'angr.png')
    splash.setWindowIcon(QIcon(icon_location))
    splash.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.setEnabled(False)
    splash.show()
    app.processEvents()

    from .logic import GlobalInfo
    from .ui.css import CSS
    from .ui.main_window import MainWindow

    # Load fonts
    QFontDatabase.addApplicationFont(os.path.join(FONT_LOCATION, "SourceCodePro-Regular.ttf"))

    GlobalInfo.gui_thread = threading.get_ident()

    # apply the CSS
    app.setStyleSheet(CSS.global_css())

    file_to_open = filepath if filepath else sys.argv[1] if len(sys.argv) > 1 else None
    main_window = MainWindow()
    splash.finish(main_window)

    if file_to_open is not None:
        main_window.load_file(file_to_open)

    app.exec_()

if __name__ == '__main__':
    main()
