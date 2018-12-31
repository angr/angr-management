
from ..utils.graph import to_supergraph

def edge_qualifies(data):
    return data['type'] not in ('call', 'return_from_call')


class FunctionGraph:

    def __init__(self, function):
        self.function = function
        self.edges = None
        self._supergraph = None

    @property
    def supergraph(self):
        if self._supergraph is not None:
            return self._supergraph

        self._supergraph = to_supergraph(self.function.transition_graph)
        self.edges = [(str(from_.addr), str(to.addr)) for (from_, to, data) in self._supergraph.edges(data=True) if
                      edge_qualifies(data)
                      ]

        return self._supergraph
