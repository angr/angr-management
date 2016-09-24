import networkx
from atom.api import List, Typed, ForwardTyped, observe
from enaml.core.declarative import d_
from enaml.widgets.frame import Frame
from enaml.widgets.control import ProxyControl

from ..data.function_graph import FunctionGraph


class ProxyFlowGraph(ProxyControl):
    declaration = ForwardTyped(lambda: FlowGraph)


class FlowGraph(Frame):

    supergraph = d_(Typed(networkx.DiGraph))

    func_graph = d_(Typed(FunctionGraph))

    #: The "selected" node that should be visible
    selected = d_(Typed(str))

    proxy = Typed(ProxyFlowGraph)

    hug_width = 'weak'
    hug_height = 'weak'

    def child_added(self, child):
        super(FlowGraph, self).child_added(child)

    @observe('selected')
    def update(self, change):
        self.request_relayout()
