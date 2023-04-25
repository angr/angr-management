from angrmanagement.utils.graph import to_supergraph


def edge_qualifies(data):
    return data["type"] not in ("call", "return_from_call")


class FunctionGraph:
    def __init__(self, function, exception_edges=True):
        self.function = function
        self.exception_edges = exception_edges
        self.edges = None
        self._supergraph = None

    def clear_cache(self):
        self._supergraph = None
        self.edges = None

    @property
    def supergraph(self):
        if self._supergraph is not None:
            return self._supergraph

        self._supergraph = to_supergraph(self.function.transition_graph_ex(exception_edges=self.exception_edges))
        self.edges = [
            (str(from_.addr), str(to.addr))
            for (from_, to, data) in self._supergraph.edges(data=True)
            if edge_qualifies(data)
        ]

        return self._supergraph
