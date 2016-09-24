
from atom.api import Atom, List, Int, Bool, Typed, observe

from enaml.core.api import d_

from ..utils.graph import to_supergraph

def edge_qualifies(data):
    return data['type'] not in ('call', 'return_from_call')

class FunctionGraph(Atom):
    function = d_(Typed(object))
    edges = List()
    supergraph = d_(Typed(object))

    ready = Bool(False)

    @observe('function')
    def update(self, changes):

        if self.function is not None:
            supergraph = to_supergraph(self.function.graph)
            self.edges = [(str(from_.addr), str(to.addr)) for (from_, to, data) in supergraph.edges(data=True) if
                          edge_qualifies(data)
                          ]

            # do it in the end, since supergraph is being observed on by the UI
            # self.edges must be initialized before UI draws any CFGNode
            self.supergraph = supergraph
