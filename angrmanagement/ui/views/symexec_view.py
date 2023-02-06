from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDockWidget, QHBoxLayout, QMainWindow

from angrmanagement.data.instance import ObjectContainer
from angrmanagement.ui.widgets.qpathtree import QPathTree
from angrmanagement.ui.widgets.qsimulation_managers import QSimulationManagers
from angrmanagement.ui.widgets.state_inspector import StateInspector

from .view import BaseView


class SymexecView(BaseView):
    def __init__(self, instance, *args, **kwargs):
        super().__init__("symexec", instance, *args, **kwargs)

        self.base_caption = "Symbolic Execution"

        self._pathtree: QPathTree
        self._simgrs: QSimulationManagers
        self._state_viewer: StateInspector

        # I think the best way to do this is for this to be a container containing the container containing the simgr?
        self.current_simgr = ObjectContainer(None, name="Active simulation manager")
        self.current_state = ObjectContainer(None, name="Selected state")

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
        self.current_simgr.am_event(src="from above")

    def select_states(self, states):
        self._simgrs.select_states(states)

    def view_state(self, state):
        self._state_viewer.state = state

        # push namespace into the console
        view = self.instance.workspace.view_manager.first_view_in_category("console")
        if view is not None:
            view.push_namespace(
                {
                    "state": state,
                }
            )

    def avoid_addr_in_exec(self, addr):
        self._simgrs.add_avoid_address(addr)

    def find_addr_in_exec(self, addr):
        self._simgrs.add_find_address(addr)

    def remove_avoid_addr_in_exec(self, addr):
        self._simgrs.remove_avoid_address(addr)

    def remove_find_addr_in_exec(self, addr):
        self._simgrs.remove_find_address(addr)

    def redraw_graph(self):
        if self.graph is not None:
            self.graph.viewport().update()

    def switch_to_disassembly_view(self):
        if self._selected_state_block:
            addr = self._selected_state_block.state.addr
            self._switch_to_disassembly_view(addr)

    #
    # Events
    #

    def closeEvent(self, _):
        """
        Close children before exiting
        """
        self._simgrs.close()

    #
    # Initialization
    #

    def _init_widgets(self):
        main = QMainWindow()
        main.setWindowFlags(Qt.Widget)

        # main.setCorner(Qt.TopLeftCorner, Qt.TopDockWidgetArea)
        # main.setCorner(Qt.TopRightCorner, Qt.RightDockWidgetArea)

        pathtree = QPathTree(self.current_simgr, self.current_state, self, self.instance.workspace, parent=main)
        pathtree_dock = QDockWidget("PathTree", pathtree)
        main.setCentralWidget(pathtree_dock)
        # main.addDockWidget(Qt.BottomDockWidgetArea, pathtree_dock)
        pathtree_dock.setWidget(pathtree)

        simgrs = QSimulationManagers(self.instance, self.current_simgr, self.current_state, parent=main)
        simgrs_dock = QDockWidget("SimulationManagers", simgrs)
        main.addDockWidget(Qt.RightDockWidgetArea, simgrs_dock)
        simgrs_dock.setWidget(simgrs)

        state_viewer = StateInspector(self.instance.workspace, self.current_state, parent=self)
        state_viewer_dock = QDockWidget("Selected State", state_viewer)
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
        if len(self.view_manager.views_by_category["disassembly"]) == 1:
            disasm_view = self.instance.workspace.view_manager.first_view_in_category("disassembly")
        else:
            disasm_view = self.instance.workspace.view_manager.current_view_in_category("disassembly")
        disasm_view.jump_to(addr)

        self.instance.workspace.raise_view(disasm_view)
