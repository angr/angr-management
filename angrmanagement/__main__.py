
import sys
import os
# make pyqode happy
os.environ['QT_API'] = 'pyside'
import thread


def check_dependencies():

    try:
        import PySide
    except ImportError:
        sys.stderr.write("Cannot find PySide package. You may install it via pip:\n" +
                         "    pip install pyside\n")
        return False

    try:
        import pyqode.core
        import pyqode.python
    except ImportError:
        sys.stderr.write("Cannot find pyqode package. You may install it via pip:\n" +
                         "    pip install pyqode.core pyqode.python\n")
        return False

    return True


def main():

    if not check_dependencies():
        sys.exit(1)

    from PySide.QtGui import QApplication

    from .logic import GlobalInfo
    from .ui.css import CSS
    from .ui.main_window import MainWindow

    app = QApplication(sys.argv)

    GlobalInfo.gui_thread = thread.get_ident()
    MainWindow(file_to_open=sys.argv[1] if len(sys.argv) > 1 else None)

    app.setStyleSheet(CSS.global_css())

    app.exec_()

if __name__ == '__main__':
    main()
