from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QHBoxLayout

from angrmanagement.present.dependencies import DependencyNode, dependency_graph, is_shown
from angrmanagement.present.graphs import convert_graph
from angrmanagement.ui.widgets.qdep_graph import QDependencyGraph
from angrmanagement.ui.widgets.qdepgraph_block import QDepGraphBlock

from .view import InstanceView

if TYPE_CHECKING:
    import networkx
    from angr.knowledge_plugins.key_definitions.atoms import Atom
    from angr.knowledge_plugins.key_definitions.definition import Definition

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class DependencyView(InstanceView):
    """
    Creates view for dependency analysis.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("dependencies", workspace, default_docking_position, instance)

        self.base_caption = "Dependencies"

        # UI widgets
        self._graph_widget: QDependencyGraph = None

        # data
        self.sink_atom: Atom | None = None
        self.sink_ins_addr: int | None = None
        self.closures: dict[Definition, networkx.DiGraph] | None = None
        self._graph: networkx.DiGraph | None = None
        self.hovered_block: QDepGraphBlock | None = None

        self._init_widgets()
        self._register_events()

    def hover_enter_block(self, block: QDepGraphBlock) -> None:
        self.hovered_block = block
        if self._graph_widget is not None:
            self._graph_widget.on_block_hovered(block)
        self.redraw_graph()

    def hover_leave_block(self) -> None:
        self.hovered_block = None
        self.redraw_graph()

    def on_screen_changed(self) -> None:
        if self._graph_widget is not None:
            self._graph_widget.refresh()

    def reload(self) -> None:
        if self._graph_widget is None:
            return
        # re-generate the graph
        if not self.closures:
            self._graph = None
            self._graph_widget.graph = None
            self._graph_widget.request_relayout()
            return

        self._graph = self._create_ui_graph()
        self._graph_widget.graph = self._graph

    def redraw_graph(self) -> None:
        if self._graph_widget is not None:
            self._graph_widget.viewport().update()

    def sizeHint(self):
        return QSize(400, 800)

    def _init_widgets(self) -> None:
        self._graph_widget = QDependencyGraph(self.instance, self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._graph_widget)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

    def _register_events(self) -> None:
        self.workspace.current_screen.am_subscribe(self.on_screen_changed)

    def _convert_node(self, node: Definition, converted: dict[Definition, QDepGraphBlock]) -> QDepGraphBlock | None:
        if node in converted:
            return converted[node]
        if not is_shown(self.instance.project, node):
            return None
        new_node = QDepGraphBlock(False, self, definition=node, addr=node.codeloc.ins_addr)
        converted[node] = new_node
        return new_node

    # def _is_edge_in_graph(self):
    def _create_ui_graph(self) -> networkx.DiGraph:
        graph, _sink = dependency_graph(self.instance.project, self.closures or {}, self.sink_atom, self.sink_ins_addr)
        blocks: dict[DependencyNode, QDepGraphBlock] = {}

        def convert(node: DependencyNode, _converted) -> QDepGraphBlock:
            if node not in blocks:
                fields: dict[str, Any] = {"definition": node.definition, "atom": node.atom, "addr": node.addr}
                blocks[node] = QDepGraphBlock(False, self, **fields)
            return blocks[node]

        return convert_graph(graph, convert)
