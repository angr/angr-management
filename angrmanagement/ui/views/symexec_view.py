from PySide2.QtWidgets import QMainWindow, QHBoxLayout, QDockWidget
from PySide2.QtCore import Qt

from ...data.instance import ObjectContainer
from ..widgets.state_inspector import StateInspector
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

        # I think the best way to do this is for this to be a container containing the container containing the simgr?
        self.current_simgr = ObjectContainer(None, name='Active simulation manager')
        self.current_state = ObjectContainer(None, name='Selected state')

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
        pass

    def select_simgr(self, simgr):
        self.current_simgr.am_obj = simgr
        self.current_simgr.am_event(src='from above')

    def view_state(self, state):
        self._state_viewer.state = state

        # push namespace into the console
        self.workspace.view_manager.first_view_in_category('console').push_namespace({
            'state': state,
        })

    def avoid_addr_in_exec(self, addr):
        self._simgrs.add_avoid_address(addr)

    def redraw_graph(self):
        if self.graph is not None:
            self.graph.viewport().update()

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

        pathtree = QPathTree(self.current_simgr, self.current_state, self, self.workspace, parent=main)
        pathtree_dock = QDockWidget('PathTree', pathtree)
        main.setCentralWidget(pathtree_dock)
        # main.addDockWidget(Qt.BottomDockWidgetArea, pathtree_dock)
        pathtree_dock.setWidget(pathtree)

        simgrs = QSimulationManagers(self.workspace.instance, self.current_simgr, self.current_state, parent=main)
        simgrs_dock = QDockWidget('SimulationManagers', simgrs)
        main.addDockWidget(Qt.RightDockWidgetArea, simgrs_dock)
        simgrs_dock.setWidget(simgrs)

        state_viewer = StateInspector(self.workspace, self.current_state, parent=self)
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
    # Private methods
    #

    def _switch_to_disassembly_view(self, addr):
        disasm_view = self.workspace.view_manager.first_view_in_category('disassembly')
        disasm_view.jump_to(addr)

        self.workspace.raise_view(disasm_view)
