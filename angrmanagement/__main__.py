import sys

import enaml
from enaml.qt.qt_application import QtApplication

from .data.instance import Instance
import angr

if __name__ == '__main__':
    with enaml.imports():
        from ui.main import Main

    if len(sys.argv) >= 2:
        proj = angr.Project(sys.argv[1], load_options={'auto_load_libs': False})
        inst = Instance(proj=proj)
    else:
        inst = None

    app = QtApplication()

    view = Main(inst=inst)
    view.show()

    app.start()
