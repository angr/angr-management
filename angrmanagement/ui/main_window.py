
import sys

from PySide.QtGui import QMainWindow, QDockWidget, QListWidget, QTabWidget
from PySide.QtCore import Qt, QSize, QEvent

import angr

from ..data.instance import Instance
from .menus.file_menu import FileMenu
from .workspace import Workspace
from .dialogs.load_binary import LoadBinary


class MainWindow(QMainWindow):
    """
    The main window of angr management.
    """
    def __init__(self, file_to_open=None, parent=None):
        super(MainWindow, self).__init__(parent)

        # initialization
        self.caption = "angr Management"
        self.setMinimumSize(QSize(800, 800))
        self.setDockNestingEnabled(True)

        self.workspace = None

        self._init_menus()
        self._init_workspace()

        # I'm ready to show off!
        self.show()

        if file_to_open is not None:
            # load a binary
            load_binary_dialog = LoadBinary(file_to_open)
            load_binary_dialog.exec_()

            if load_binary_dialog.cfg_args is not None:
                # load the binary
                self._load_binary(file_to_open, cfg_args=load_binary_dialog.cfg_args)

    #
    # Properties
    #

    @property
    def caption(self):
        return self.getWindowTitle()

    @caption.setter
    def caption(self, v):
        self.setWindowTitle(v)

    #
    # Widgets
    #



    #
    # Menus
    #

    def _init_menus(self):
        fileMenu = FileMenu(self)
        self.menuBar().addMenu(fileMenu.qmenu())

    #
    # Workspace
    #

    def _init_workspace(self):
        wk = Workspace(self)
        self.workspace = wk

        right_dockable_views = [ dock for dock in self.workspace.dockable_views
                                 if dock.widget().default_docking_position == 'right' ]

        for d0, d1 in zip(right_dockable_views, right_dockable_views[1:]):
            self.tabifyDockWidget(d0, d1)
        right_dockable_views[0].raise_()

        self.setTabPosition(Qt.RightDockWidgetArea, QTabWidget.North)

    #
    # Event
    #

    def event(self, event):

        if event.type() == QEvent.User:
            # our event callback

            try:
                event.result = event.execute()
            except Exception:
                event.exception = sys.exc_info()
            event.event.set()

            return True

        return super(MainWindow, self).event(event)

    #
    # Actions
    #

    def reload(self):
        self.workspace.reload()

    def load_binary(self):
        print "load binary"

    def quit(self):
        self.close()

    #
    # Private methods
    #

    def _load_binary(self, file_path, cfg_args=None):

        if cfg_args is None:
            cfg_args = { }

        inst = Instance(project=angr.Project(file_path, load_options={'auto_load_libs': False}))
        self.workspace.set_instance(inst)
        inst.initialize(cfg_args=cfg_args)
