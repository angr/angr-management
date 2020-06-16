from typing import Dict, Any, Optional

import networkx

from PySide2.QtWidgets import QHBoxLayout
from PySide2.QtCore import QSize

from angr.knowledge_plugins.key_definitions.definition import Definition

from ..widgets.qdep_graph import QDependencyGraph
from ..widgets.qdepgraph_block import QDepGraphBlock
from .view import BaseView


class DependencyView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('dependencies', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Dependencies'
        self.workspace = workspace

        # UI widgets
        self._graph_widget: QDependencyGraph = None

        # data
        self.closures: Optional[Dict[Definition,networkx.DiGraph]] = None
        self._graph: Optional[networkx.DiGraph] = None
        self.hovered_block: Optional[QDepGraphBlock] = None

        self._init_widgets()

    def hover_enter_block(self, block: QDepGraphBlock):
        self.hovered_block = block
        if self._graph_widget is not None:
            self._graph_widget.on_block_hovered(block)
        self.redraw_graph()

    def hover_leave_block(self, block: QDepGraphBlock):
        self.hovered_block = None
        self.redraw_graph()

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

        self._graph_widget = QDependencyGraph(self.workspace, self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._graph_widget)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

    def _convert_node(self, node: Definition, converted: Dict[Definition,QDepGraphBlock]) -> QDepGraphBlock:
        if node in converted:
            return converted[node]
        new_node = QDepGraphBlock(False, self, node.codeloc.ins_addr)
        converted[node] = new_node
        return new_node

    def _create_ui_graph(self) -> networkx.DiGraph:

        g = networkx.DiGraph()
        source_node = QDepGraphBlock(False, self, 0)
        g.add_node(source_node)

        converted = { }
        for key, graph in self.closures.items():
            node = self._convert_node(key, converted)
            g.add_edge(node, source_node)

            for node_ in graph.nodes:
                node = self._convert_node(node_, converted)
                g.add_node(node)
            for src_, dst_ in graph.edges:
                src = self._convert_node(src_, converted)
                dst = self._convert_node(dst_, converted)
                g.add_edge(src, dst)

        return g
