
from PySide.QtGui import QMainWindow, QHBoxLayout, QDockWidget
from PySide.QtCore import Qt
from angrmanagement.ui.widgets.state_inspector import StateInspector

from ..widgets.qpathtree import QPathTree
from ..widgets.qsimulation_managers import QSimulationManagers
from .view import BaseView


class SymexecView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(SymexecView, self).__init__('symexec', workspace, *args, **kwargs)

        self.caption = 'Symbolic Execution'

        self._pathtree = None  # type: QPathTree
        self._simgrs = None  # type: QSimulationManagers
        self._state_viewer = None  # type: StateInspector

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
        self._state_viewer.state = state

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

        state_viewer = StateInspector(self.workspace, parent=self)
        state_viewer_dock = QDockWidget('Selected State', state_viewer)
        main.addDockWidget(Qt.RightDockWidgetArea, state_viewer_dock)
        state_viewer_dock.setWidget(state_viewer)

        self._pathtree = pathtree
        self._simgrs = simgrs
        self._state_viewer = state_viewer

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
