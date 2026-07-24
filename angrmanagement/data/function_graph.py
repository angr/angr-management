from __future__ import annotations

from angrmanagement.utils.graph import to_supergraph


def edge_qualifies(data) -> bool:
    return data["type"] not in ("call", "return_from_call")


class FunctionGraph:
    def __init__(self, function, exception_edges: bool = True) -> None:
        self.function = function
        self.exception_edges = exception_edges
        self.edges = None
        self._supergraph = None

    def clear_cache(self) -> None:
        self._supergraph = None
        self.edges = None

    @property
    def supergraph(self):
        if self._supergraph is not None:
            return self._supergraph

        function = self.function
        if not function.normalized:
            # during CFG recovery (and for CFGs recovered with normalize=False), functions in the knowledge base are
            # not normalized and may contain overlapping blocks (e.g., a jump-target block that also exists inside a
            # longer fall-through block); display a normalized copy instead. Function.copy() does not register the
            # copy anywhere, and Function.normalize() does not touch the CFG model, so analysis state is unaffected.
            try:
                function = self.function.copy()
                function.normalize()
            except (RuntimeError, KeyError, AttributeError):
                # the function may be mutated by the CFG recovery job thread while we copy it; fall back to the raw
                # function for this round - the next reload retries
                function = self.function

        self._supergraph = to_supergraph(function.transition_graph_ex(exception_edges=self.exception_edges))
        self.edges = [
            (str(from_.addr), str(to.addr))
            for (from_, to, data) in self._supergraph.edges(data=True)
            if edge_qualifies(data)
        ]

        return self._supergraph
