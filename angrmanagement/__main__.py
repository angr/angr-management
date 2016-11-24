import sys

import enaml
from enaml.qt.qt_application import QtApplication

from .data.instance import Instance
import angr

def main():
    with enaml.imports():
        from ui.main import Main

    if len(sys.argv) >= 2:
        file_to_open = sys.argv[1]
    else:
        file_to_open = None

    app = QtApplication()

    view = Main(file_to_open=file_to_open)
    view.show()

    app.start()

if __name__ == '__main__':
    main()
