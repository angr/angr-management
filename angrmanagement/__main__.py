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


def main():

    if not check_dependencies():
        sys.exit(1)

    set_app_user_model_id()

    from PySide2.QtWidgets import QApplication

    from .logic import GlobalInfo
    from .ui.css import CSS
    from .ui.main_window import MainWindow

    app = QApplication(sys.argv)

    GlobalInfo.gui_thread = threading.get_ident()

    # apply the CSS
    app.setStyleSheet(CSS.global_css())

    MainWindow(file_to_open=sys.argv[1] if len(sys.argv) > 1 else None)

    app.exec_()

if __name__ == '__main__':
    main()
