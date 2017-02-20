
from PySide.QtGui import QMainWindow, QHBoxLayout, QDockWidget
from PySide.QtCore import Qt

from ..widgets.qpathtree import QPathTree
from ..widgets.qpath_groups import QPathGroups
from .view import BaseView


class SymexecView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(SymexecView, self).__init__('symexec', workspace, *args, **kwargs)

        self.caption = 'Symbolic Execution'

        self._pathtree = None  # type: QPathTree
        self._pathgroups = None  # type: QPathGroups

        self._init_widgets()

    #
    # Public methods
    #

    def reload(self):
        self._pathgroups.path_groups = self.workspace.instance.path_groups

        self._pathgroups.on_pathgroup_selection = self._on_pathgroup_selection

    def select_pathgroup(self, pg):
        self._pathgroups.select_pathgroup(pg)

    #
    # Initialization
    #

    def _init_widgets(self):

        main = QMainWindow()
        main.setWindowFlags(Qt.Widget)

        pathtree = QPathTree(main)
        pathtree_dock = QDockWidget('PathTree', pathtree)
        main.addDockWidget(Qt.BottomDockWidgetArea, pathtree_dock)
        pathtree_dock.setWidget(pathtree)

        pathgroups_logic = self.workspace.instance.path_groups if self.workspace.instance is not None else None
        pathgroups = QPathGroups(pathgroups_logic, main)
        pathgroups_dock = QDockWidget('PathGroups', pathgroups)
        main.addDockWidget(Qt.TopDockWidgetArea, pathgroups_dock)
        pathgroups_dock.setWidget(pathgroups)

        self._pathtree = pathtree
        self._pathgroups = pathgroups

        main_layout = QHBoxLayout()
        main_layout.addWidget(main)

        self.setLayout(main_layout)

    #
    # Event handlers
    #

    def _on_pathgroup_selection(self, idx):
        if idx != -1:
            pg = self._pathgroups.get_pathgroup(idx)

            self._pathtree.pathgroup = pg
