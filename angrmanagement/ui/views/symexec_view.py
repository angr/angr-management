
from PySide.QtGui import QMainWindow, QHBoxLayout, QDockWidget
from PySide.QtCore import Qt, QSize

from ..widgets.qpathtree import QPathTree
from ..widgets.qsimulation_managers import QSimulationManagers
from .view import BaseView
from ..widgets.qregister_viewer import QRegisterViewer
from ..widgets.qmemory_viewer import QMemoryViewer
from ..widgets.qvextemps_viewer import QVEXTempsViewer


class SymexecView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(SymexecView, self).__init__('symexec', workspace, *args, **kwargs)

        self.caption = 'Symbolic Execution'

        self._pathtree = None  # type: QPathTree
        self._simgrs = None  # type: QSimulationManagers
        self._register_viewer = None  # type: QRegisterViewer
        self._memory_viewer = None  # type: QMemoryViewer
        self._vextemps_viewer = None  # type: QVEXTempsViewer

        self._selected_state_block = None

        self._init_widgets()

    #
    # Properties
    #

    @property
    def graph(self):
        if self._pathtree is None:
            return None
        return self._pathtree._graph

    #
    # Public methods
    #

    def reload(self):
        self._simgrs.simgrs = self.workspace.instance.simgrs

        self._simgrs.on_simgr_selection = self._on_simgr_selection

    def select_simgr_desc(self, pg_desc):
        self._simgrs.select_simgr_desc(pg_desc)

    def view_state(self, state):
        self._register_viewer.state = state
        self._memory_viewer.state = state
        self._vextemps_viewer.state = state

        # push namespace into the console
        self.workspace.views_by_category['console'][0].push_namespace({
            'state': state,
        })

    def avoid_addr_in_exec(self, addr):

        self._simgrs.add_avoid_address(addr)

    def redraw_graph(self):
        if self.graph is not None:
            self.graph.viewport().update()

    def select_state_block(self, state_block):
        if self._selected_state_block is not None:
            self._selected_state_block.selected = False
            self._selected_state_block = None
        self._selected_state_block = state_block

    def deselect_state_block(self, state_block):
        if self._selected_state_block is state_block:
            self._selected_state_block = None

    def switch_to_disassembly_view(self):
        if self._selected_state_block:
            addr = self._selected_state_block.state.addr
            self._switch_to_disassembly_view(addr)

    #
    # Initialization
    #

    def _init_widgets(self):

        main = QMainWindow()
        main.setWindowFlags(Qt.Widget)

        # main.setCorner(Qt.TopLeftCorner, Qt.TopDockWidgetArea)
        # main.setCorner(Qt.TopRightCorner, Qt.RightDockWidgetArea)

        pathtree = QPathTree(self, self.workspace, parent=main)
        pathtree_dock = QDockWidget('PathTree', pathtree)
        main.setCentralWidget(pathtree_dock)
        # main.addDockWidget(Qt.BottomDockWidgetArea, pathtree_dock)
        pathtree_dock.setWidget(pathtree)

        simgrs_logic = self.workspace.instance.simgrs if self.workspace.instance is not None else None
        simgrs = QSimulationManagers(simgrs_logic, main)
        pathgroups_dock = QDockWidget('SimulationManagers', simgrs)
        main.addDockWidget(Qt.RightDockWidgetArea, pathgroups_dock)
        pathgroups_dock.setWidget(simgrs)

        reg_viewer = QRegisterViewer(self, self.workspace)
        reg_viewer_dock = QDockWidget('Register Viewer', reg_viewer)
        main.addDockWidget(Qt.RightDockWidgetArea, reg_viewer_dock)
        reg_viewer_dock.setWidget(reg_viewer)

        mem_viewer = QMemoryViewer(self, self.workspace)
        mem_viewer_dock = QDockWidget('Memory Viewer', mem_viewer)
        main.addDockWidget(Qt.RightDockWidgetArea, mem_viewer_dock)
        mem_viewer_dock.setWidget(mem_viewer)

        vextemps_viewer = QVEXTempsViewer(self, self.workspace)
        vextemps_viewer_dock = QDockWidget('VEX Temps Viewer', vextemps_viewer)
        main.addDockWidget(Qt.RightDockWidgetArea, vextemps_viewer_dock)
        vextemps_viewer_dock.setWidget(vextemps_viewer)

        main.tabifyDockWidget(reg_viewer_dock, mem_viewer_dock)
        main.tabifyDockWidget(mem_viewer_dock, vextemps_viewer_dock)
        reg_viewer_dock.raise_()

        self._pathtree = pathtree
        self._simgrs = simgrs
        self._register_viewer = reg_viewer
        self._memory_viewer = mem_viewer
        self._vextemps_viewer = vextemps_viewer

        main_layout = QHBoxLayout()
        main_layout.addWidget(main)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    #
    # Event handlers
    #

    def _on_simgr_selection(self, idx):
        if idx != -1:
            simgr = self._simgrs.get_simgr(idx)

            self._pathtree.simgr = simgr

    #
    # Private methods
    #

    def _switch_to_disassembly_view(self, addr):
        disasm_view = self.workspace.views_by_category['disassembly'][0]
        disasm_view.jump_to(addr)

        self.workspace.raise_view(disasm_view)
