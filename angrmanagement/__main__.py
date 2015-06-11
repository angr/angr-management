import sys

import enaml
from enaml.qt.qt_application import QtApplication

import angr

if __name__ == '__main__':
    with enaml.imports():
        from ui.main import Main

    proj = angr.Project(sys.argv[1])

    app = QtApplication()

    view = Main(proj=proj)
    view.show()

    app.start()
