from typing import Dict, Optional, Set, TYPE_CHECKING

import networkx

from PySide6.QtWidgets import QHBoxLayout
from PySide6.QtCore import QSize

from angrmanagement.ui.views.view import BaseView
from angrmanagement.ui.widgets.qproximity_graph import QProximityGraph
from angrmanagement.ui.widgets.qproximitygraph_block import QProximityGraphCallBlock, QProximityGraphStringBlock, \
    QProximityGraphFunctionBlock, QProximityGraphBlock

from angr.analyses.proximity_graph import BaseProxiNode, FunctionProxiNode, StringProxiNode, CallProxiNode, \
    VariableProxiNode

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function


class ProximityView(BaseView):
    """
    Proximity View
    """

    def __init__(self, instance, default_docking_position, *args, **kwargs):
        super().__init__('proximity', instance, default_docking_position, *args, **kwargs)

        self.base_caption = 'Proximity'
        self.instance = instance

        self._function: Optional['Function'] = None
        self._expand_function_addrs: Set[int] = set()

        # UI widgets
        self._graph_widget: QProximityGraph = None

        # data
        self._proximity_graph: Optional[networkx.DiGraph] = None  # generated by ProximityGraphAnalysis
        self._graph: Optional[networkx.DiGraph] = None
        self.hovered_block: Optional[QProximityGraphBlock] = None

        self._init_widgets()
        self._register_events()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v):
        if v is not None and v is not self._function:
            self._function = v
            self._expand_function_addrs.clear()
            self.run_analysis()

    def get_decompilation(self):
        # FIXME: Get rid of this fucker and replace it with the new decompilation manager
        inst = self.instance
        dec = inst.project.analyses.Decompiler(
            self.function,
            cfg=self.instance.cfg,
        )
        return dec

    def run_analysis(self):
        dec = self.get_decompilation()

        inst = self.instance
        prox = inst.project.analyses.Proximity(
            self.function,
            inst.cfg,
            inst.kb.xrefs,
            decompilation=dec,
            expand_funcs=self._expand_function_addrs,
        )
        self._proximity_graph = prox.graph

        self.reload()

    def hover_enter_block(self, block: QProximityGraphBlock):
        self.hovered_block = block
        if self._graph_widget is not None:
            self._graph_widget.on_block_hovered(block)
        self.redraw_graph()

    def hover_leave_block(self, block: QProximityGraphBlock):  # pylint: disable=unused-argument
        self.hovered_block = None
        self.redraw_graph()

    def expand_function(self, func):
        if func.addr not in self._expand_function_addrs:
            self._expand_function_addrs.add(func.addr)
            # re-run the analysis
            self.run_analysis()

    def collapse_function(self, func):
        if func.addr in self._expand_function_addrs:
            self._expand_function_addrs.discard(func.addr)
            # re-run the analysis
            self.run_analysis()

    def on_screen_changed(self):
        if self._graph_widget is not None:
            self._graph_widget.refresh()

    def reload(self):
        if self._graph_widget is None:
            return
        # re-generate the graph
        if not self._proximity_graph:
            self._graph = None
            self._graph_widget.graph = None
            self._graph_widget.request_relayout()
            return

        self._graph = self._create_ui_graph()
        self._graph_widget.graph = self._graph

    def clear(self):
        self._proximity_graph = None
        self.reload()

    def redraw_graph(self):
        if self._graph_widget is not None:
            self._graph_widget.viewport().update()

    def sizeHint(self):
        return QSize(400, 800)

    def _init_widgets(self):

        self._graph_widget = QProximityGraph(self.instance, self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._graph_widget)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

    def _register_events(self):
        self.instance.workspace.current_screen.am_subscribe(self.on_screen_changed)

    def _convert_node(self, node: BaseProxiNode,
                      converted: Dict[BaseProxiNode, QProximityGraphBlock]) -> Optional[QProximityGraphBlock]:
        if node in converted:
            return converted[node]

        if isinstance(node, StringProxiNode):
            new_node = QProximityGraphStringBlock(False, self, node)
        elif isinstance(node, FunctionProxiNode):
            new_node = QProximityGraphFunctionBlock(False, self, node)
        elif isinstance(node, CallProxiNode):
            new_node = QProximityGraphCallBlock(False, self, node)
        elif isinstance(node, VariableProxiNode):
            new_node = QProximityGraphBlock
        elif isinstance(node, BaseProxiNode):
            new_node = QProximityGraphBlock(False, self, node)
        else:
            raise TypeError(f"Unsupported type of proximity node {type(node)}.")
        converted[node] = new_node
        return new_node

    def _create_ui_graph(self) -> networkx.DiGraph:

        g = networkx.DiGraph()

        converted = {}
        for proxi_node in self._proximity_graph.nodes():
            node = self._convert_node(proxi_node, converted)
            if node is not None:
                g.add_node(node)

        for n0, n1 in self._proximity_graph.edges():
            n0_ = self._convert_node(n0, converted)
            n1_ = self._convert_node(n1, converted)

            g.add_edge(n0_, n1_)

        return g
