from typing import TYPE_CHECKING, Dict, Optional

import networkx
from angr import SIM_PROCEDURES
from angr.code_location import ExternalCodeLocation
from PySide6.QtCore import QSize
from PySide6.QtWidgets import QHBoxLayout

from angrmanagement.ui.widgets.qdep_graph import QDependencyGraph
from angrmanagement.ui.widgets.qdepgraph_block import QDepGraphBlock

from .view import BaseView

if TYPE_CHECKING:
    from angr.knowledge_plugins.key_definitions.atoms import Atom
    from angr.knowledge_plugins.key_definitions.definition import Definition


class DependencyView(BaseView):
    """
    Creates view for dependency analysis.
    """

    def __init__(self, workspace, instance, default_docking_position, *args, **kwargs):
        super().__init__("dependencies", workspace, instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Dependencies"

        # UI widgets
        self._graph_widget: QDependencyGraph = None

        # data
        self.sink_atom: Optional[Atom] = None
        self.sink_ins_addr: Optional[int] = None
        self.closures: Optional[Dict[Definition, networkx.DiGraph]] = None
        self._graph: Optional[networkx.DiGraph] = None
        self.hovered_block: Optional[QDepGraphBlock] = None

        self._init_widgets()
        self._register_events()

    def hover_enter_block(self, block: QDepGraphBlock):
        self.hovered_block = block
        if self._graph_widget is not None:
            self._graph_widget.on_block_hovered(block)
        self.redraw_graph()

    def hover_leave_block(self):
        self.hovered_block = None
        self.redraw_graph()

    def on_screen_changed(self):
        if self._graph_widget is not None:
            self._graph_widget.refresh()

    def reload(self):
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

    def redraw_graph(self):
        if self._graph_widget is not None:
            self._graph_widget.viewport().update()

    def sizeHint(self):
        return QSize(400, 800)

    def _init_widgets(self):
        self._graph_widget = QDependencyGraph(self.instance, self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._graph_widget)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

    def _register_events(self):
        self.workspace.current_screen.am_subscribe(self.on_screen_changed)

    def _convert_node(
        self, node: "Definition", converted: Dict["Definition", QDepGraphBlock]
    ) -> Optional[QDepGraphBlock]:
        if node in converted:
            return converted[node]

        # skip external
        if isinstance(node.codeloc, ExternalCodeLocation):
            return None

        if self.instance.project.is_hooked(node.codeloc.block_addr):
            hook = self.instance.project.hooked_by(node.codeloc.block_addr)
            if isinstance(
                hook,
                (SIM_PROCEDURES["stubs"]["UnresolvableJumpTarget"], SIM_PROCEDURES["stubs"]["UnresolvableCallTarget"]),
            ):
                return None

        new_node = QDepGraphBlock(False, self, definition=node, addr=node.codeloc.ins_addr)
        converted[node] = new_node
        return new_node

    # def _is_edge_in_graph(self):
    def _create_ui_graph(self) -> networkx.DiGraph:
        g = networkx.DiGraph()
        source_node = QDepGraphBlock(False, self, atom=self.sink_atom, addr=self.sink_ins_addr)
        g.add_node(source_node)
        all_graphs = networkx.compose_all(self.closures.values())
        converted = {}

        for node_ in all_graphs.nodes:
            node = self._convert_node(node_, converted)
            if node is not None:
                g.add_node(node)
            # this is a hack - we only want our sink as the only root of the dependency tree
            # TODO: Figure out why
            if all_graphs.out_degree[node_] == 0:
                g.add_edge(node, source_node)

        for src_, dst_ in all_graphs.edges:
            src = self._convert_node(src_, converted)
            dst = self._convert_node(dst_, converted)
            if src is not None and dst is not None:
                g.add_edge(src, dst)

        return g
