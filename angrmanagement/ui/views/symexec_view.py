
from PySide.QtGui import QMainWindow, QHBoxLayout, QDockWidget
from PySide.QtCore import Qt, QSize

from ..widgets.qpathtree import QPathTree
from ..widgets.qpath_groups import QPathGroups
from .view import BaseView
from ..widgets.qregister_viewer import QRegisterViewer
from ..widgets.qmemory_viewer import QMemoryViewer


class SymexecView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(SymexecView, self).__init__('symexec', workspace, *args, **kwargs)

        self.caption = 'Symbolic Execution'

        self._pathtree = None  # type: QPathTree
        self._pathgroups = None  # type: QPathGroups
        self._register_viewer = None  # type: QRegisterViewer
        self._memory_viewer = None  # type: QMemoryViewer

        self._init_widgets()

    #
    # Public methods
    #

    def reload(self):
        self._pathgroups.path_groups = self.workspace.instance.path_groups

        self._pathgroups.on_pathgroup_selection = self._on_pathgroup_selection

    def select_pathgroup_desc(self, pg_desc):
        self._pathgroups.select_pathgroup_desc(pg_desc)

    def view_path(self, path):
        self._register_viewer.state = path.state
        self._memory_viewer.state = path.state

        # push namespace into the console
        self.workspace.views_by_category['console'][0].push_namespace({
            'path': path,
            'state': path.state,
        })

    def avoid_addr_in_exec(self, addr):

        self._pathgroups.add_avoid_address(addr)

    #
    # Initialization
    #

    def _init_widgets(self):

        main = QMainWindow()
        main.setWindowFlags(Qt.Widget)

        # main.setCorner(Qt.TopLeftCorner, Qt.TopDockWidgetArea)
        # main.setCorner(Qt.TopRightCorner, Qt.RightDockWidgetArea)

        pathtree = QPathTree(self, main)
        pathtree_dock = QDockWidget('PathTree', pathtree)
        main.setCentralWidget(pathtree_dock)
        # main.addDockWidget(Qt.BottomDockWidgetArea, pathtree_dock)
        pathtree_dock.setWidget(pathtree)

        pathgroups_logic = self.workspace.instance.path_groups if self.workspace.instance is not None else None
        pathgroups = QPathGroups(pathgroups_logic, main)
        pathgroups_dock = QDockWidget('PathGroups', pathgroups)
        main.addDockWidget(Qt.RightDockWidgetArea, pathgroups_dock)
        pathgroups_dock.setWidget(pathgroups)

        reg_viewer = QRegisterViewer(self)
        reg_viewer_dock = QDockWidget('Register Viewer', reg_viewer)
        main.addDockWidget(Qt.RightDockWidgetArea, reg_viewer_dock)
        reg_viewer_dock.setWidget(reg_viewer)

        mem_viewer = QMemoryViewer(self)
        mem_viewer_dock = QDockWidget('Memory Viewer', mem_viewer)
        main.addDockWidget(Qt.RightDockWidgetArea, mem_viewer_dock)
        mem_viewer_dock.setWidget(mem_viewer)

        main.tabifyDockWidget(reg_viewer_dock, mem_viewer_dock)

        self._pathtree = pathtree
        self._pathgroups = pathgroups
        self._register_viewer = reg_viewer
        self._memory_viewer = mem_viewer

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
