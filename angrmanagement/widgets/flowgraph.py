import networkx

from atom.api import List, Typed, ForwardTyped, observe
from enaml.core.declarative import d_
from enaml.widgets.frame import Frame
from enaml.widgets.control import ProxyControl

import angr

from ..data.function_graph import FunctionGraph


class ProxyFlowGraph(ProxyControl):
    declaration = ForwardTyped(lambda: FlowGraph)


class FlowGraph(Frame):

    func_graph = d_(Typed(FunctionGraph))

    proj = d_(Typed(angr.Project))

    disasm = d_(Typed(angr.analyses.Disassembly))

    selected_function = d_(Typed(angr.knowledge.Function))

    #: The "selected" node that should be visible
    selected = d_(Typed(str))

    proxy = Typed(ProxyFlowGraph)

    hug_width = 'weak'
    hug_height = 'weak'

    def child_added(self, child):
        super(FlowGraph, self).child_added(child)

    @observe('func_graph')
    def initialize_function(self, change):
        self.disasm = self.proj.analyses.Disassembly(function=self.selected_function)

    @observe('selected')
    def update(self, change):
        self.request_relayout()
