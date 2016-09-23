import networkx
from atom.api import List, Typed, ForwardTyped
from enaml.core.declarative import d_
from enaml.widgets.frame import Frame
from enaml.widgets.control import ProxyControl


class ProxyFlowGraph(ProxyControl):
    declaration = ForwardTyped(lambda: FlowGraph)


class FlowGraph(Frame):

    supergraph = d_(Typed(networkx.DiGraph))

    #: The edges (as names) of the Graph
    edges = d_(List())

    #: The "selected" node that should be visible
    selected = d_(Typed(str))

    func_addr = d_(Typed(int))

    proxy = Typed(ProxyFlowGraph)

    hug_width = 'weak'
    hug_height = 'weak'

    def child_added(self, child):
        super(FlowGraph, self).child_added(child)

    def update(self):
        self.request_relayout()
