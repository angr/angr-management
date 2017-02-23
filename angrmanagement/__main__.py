
import sys
import thread

from PySide.QtGui import QApplication

from .logic import GlobalInfo
from .ui.css import CSS
from .ui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)

    GlobalInfo.gui_thread = thread.get_ident()
    MainWindow(file_to_open=sys.argv[1] if len(sys.argv) > 1 else None)

    app.setStyleSheet(CSS.global_css())

    app.exec_()

if __name__ == '__main__':
    main()
