from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.data_dep import MemDepNode, RegDepNode, TmpDepNode

# noinspection PyPackageRequirements
from networkx import DiGraph

# noinspection PyPackageRequirements
from PySide6 import QtCore, QtGui, QtWidgets

from angrmanagement.ui.dialogs.data_dep_graph_search import QDataDepGraphSearch
from angrmanagement.ui.widgets.qdatadep_graph import QDataDepGraph
from angrmanagement.ui.widgets.qdatadepgraph_block import QDataDepGraphBlock

from .view import InstanceView

if TYPE_CHECKING:
    from angr import SimState
    from angr.analyses import DataDependencyGraphAnalysis
    from angr.analyses.data_dep import BaseDepNode
    from capstone import CsInsn

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class DataDepView(InstanceView):
    """Workspace view used to display a data dependency graph on the screen"""

    @property
    def function(self):
        raise NotImplementedError("Does not apply!")

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("data_dependency", workspace, default_docking_position, instance)

        self.base_caption = "Data Dependency"

        self._instructions: dict[int, CsInsn] = {}
        self._end_state: SimState | None = None
        self._start_addr: int | None = None
        self._end_addr: int | None = None
        self._block_addrs: list[int] | None = None

        # UI widgets
        self._graph_widget: QDataDepGraph | None = None

        # Data
        self._data_dep: DataDependencyGraphAnalysis | None = None
        self._ddg: DiGraph | None = None  # Derived from analysis, can be full, simplified, or subgraph
        self._graph: DiGraph | None = None
        self._traced_ancestors: set[QDataDepGraphBlock] = set()
        self._traced_descendants: set[QDataDepGraphBlock] = set()

        self._init_widgets()
        self._register_events()

    @property
    def _data_dep_graph(self) -> DiGraph | None:
        return self._ddg

    @_data_dep_graph.setter
    def _data_dep_graph(self, new_ddg: DiGraph) -> None:
        self._ddg = new_ddg
        self._graph_widget.ref_graph = new_ddg

    @property
    def traced_ancestors(self) -> set[QDataDepGraphBlock]:
        return self._traced_ancestors

    def update_ancestors(self, block: QDataDepGraphBlock) -> None:
        self._traced_descendants.clear()
        self._traced_ancestors = self._graph_widget.get_ancestors(block)
        self.redraw_graph()

    @property
    def traced_descendants(self) -> set[QDataDepGraphBlock]:
        return self._traced_descendants

    def update_descendants(self, block: QDataDepGraphBlock) -> None:
        self._traced_ancestors.clear()
        self._traced_descendants = self._graph_widget.get_descendants(block)
        self.redraw_graph()

    @property
    def graph_widget(self) -> QDataDepGraph | None:
        return self._graph_widget

    @property
    def analysis_params(self) -> dict:
        return {
            "end_state": self._end_state,
            "start_addr": self._start_addr,
            "end_addr": self._end_addr,
            "block_addrs": self._block_addrs,
        }

    @analysis_params.setter
    def analysis_params(self, new_params: dict) -> None:
        if new_params == self.analysis_params:
            # Nothing new, no need to rerun analysis
            return

        try:
            self._end_state = new_params["end_state"]
            self._start_addr = new_params["start_addr"]
            self._end_addr = new_params["end_addr"]
            self._block_addrs = new_params["block_addrs"]

            self.run_analysis()
        except OSError:
            pass
        # except KeyError:
        #     _l.error("Unable to generate data dependency graph with provided parameters!")

    def run_analysis(self) -> None:
        inst = self.instance

        data_dep: DataDependencyGraphAnalysis = inst.project.analyses.DataDep(
            self._end_state,
            self._start_addr,
            self._end_addr,
            self._block_addrs,
        )

        self._data_dep = data_dep
        self._data_dep_graph = data_dep.graph
        self.reload()

    def hover_enter_block(self, block: QDataDepGraphBlock, modifiers: QtCore.Qt.KeyboardModifier) -> None:
        # If the user is holding down 'Control' while hovering, should show descendants instead
        if modifiers & QtCore.Qt.KeyboardModifier.ControlModifier:
            self._traced_descendants = self._graph_widget.get_descendants(block)
        else:
            self._traced_ancestors = self._graph_widget.get_ancestors(block)

        # if self._graph_widget is not None:
        #     self._graph_widget.on_block_hovered(block)
        self.redraw_graph()

    def hover_leave_block(self) -> None:
        self._traced_ancestors.clear()
        self._traced_descendants.clear()
        self.redraw_graph()

    def on_screen_changed(self) -> None:
        if self._graph_widget is not None:
            self._graph_widget.refresh()

    def reload(self) -> None:
        if self.instance.am_none or self._graph_widget is None:
            return

        # Get all instructions in the program
        for _, func in self.instance.kb.functions.items():
            for block in func.blocks:
                disass = block.disassembly
                for ins in disass.insns:
                    self._instructions[ins.address] = ins

        # Re-Generate the graph
        if not self._data_dep:
            self._graph = None
            self._graph_widget.graph = None
            self._graph_widget.request_relayout()
            return

        self._graph = self._create_ui_graph()
        self._graph_widget.graph = self._graph

    def redraw_graph(self) -> None:
        if self._graph_widget.graph is not None:
            self._graph_widget.viewport().update()

    def sizeHint(self):
        return QtCore.QSize(400, 800)

    def _init_widgets(self) -> None:
        self._graph_widget = QDataDepGraph(self.workspace, self, self)

        h_layout = QtWidgets.QHBoxLayout(self)
        h_layout.addWidget(self._graph_widget)
        h_layout.setContentsMargins(0, 0, 0, 0)

    def _register_events(self) -> None:
        self.workspace.current_screen.am_subscribe(self.on_screen_changed)

    def _convert_node(
        self, node: BaseDepNode, converted: dict[BaseDepNode, QDataDepGraphBlock]
    ) -> QDataDepGraphBlock | None:
        if isinstance(node, MemDepNode | RegDepNode):
            cs_instr = self._instructions.get(node.ins_addr, None)
            instr = cs_instr.insn if cs_instr else None
        else:
            instr = None
        return converted.setdefault(node, QDataDepGraphBlock(False, self, node, instr))

    def _create_ui_graph(self) -> DiGraph:
        g = DiGraph()

        converted = {}
        for dep_node in self._data_dep_graph.nodes():
            node = self._convert_node(dep_node, converted)
            if node:
                g.add_node(node)

        for n0, n1 in self._data_dep_graph.edges():
            n0_ = self._convert_node(n0, converted)
            n1_ = self._convert_node(n1, converted)

            g.add_edge(n0_, n1_)

        return g

    def _graph_has_tmp_nodes(self) -> bool:
        """
        Returns whether or not the given graph has temp nodes
        """
        if not self._data_dep_graph:
            return False
        return any(node for node in self._data_dep_graph.nodes if isinstance(node, TmpDepNode))

    def use_subgraph(self, block: QDataDepGraphBlock, backwards: bool) -> None:
        dep_node = block.node
        # Determine if any temp nodes exist in the graph and, if so, include them in subgraph
        self._data_dep_graph = self._data_dep.get_data_dep(dep_node, self._graph_has_tmp_nodes(), backwards)
        self.reload()

    def _toggle_graph(self) -> None:
        """Switches the current graph being shown between the full and simplified graph"""
        if self._data_dep_graph is self._data_dep.simplified_graph:
            self._data_dep_graph = self._data_dep.graph
        elif self._data_dep_graph is self._data_dep.sub_graph:
            self._data_dep_graph = (
                self._data_dep.graph if self._graph_has_tmp_nodes() else self._data_dep.simplified_graph
            )
        else:
            self._data_dep_graph = self._data_dep.simplified_graph
        self.reload()

    #
    # Events
    #
    def keyPressEvent(self, event: QtGui.QKeyEvent) -> None:
        """
        Allow for searching for a node
        """
        key = event.key()
        modifiers = event.modifiers()

        if key == QtCore.Qt.Key.Key_F and modifiers & QtCore.Qt.KeyboardModifier.ControlModifier:
            # User would like to search
            search_dialog = QDataDepGraphSearch(self, self.graph_widget)
            search_dialog.setModal(False)
            search_dialog.show()
        else:
            super().keyPressEvent(event)

    def mousePressEvent(self, event: QtGui.QMouseEvent) -> None:
        button = event.button()

        if button == QtCore.Qt.MouseButton.RightButton and event:
            options_menu = QtWidgets.QMenu("Options", self)
            if self._data_dep_graph is self._data_dep.graph:
                toggle_text = "Hide temp nodes"
            elif self._data_dep_graph is self._data_dep.simplified_graph:
                toggle_text = "Show temp nodes"
            else:
                toggle_text = "Untrack node"

            options_menu.addAction(toggle_text, self._toggle_graph)

            # Open options menu
            options_menu.exec_(self.mapToGlobal(event.pos()))
        else:
            super().mousePressEvent(event)
