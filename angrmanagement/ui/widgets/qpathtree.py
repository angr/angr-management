import logging

import networkx
from PySide6.QtCore import QSize
from PySide6.QtWidgets import QFrame, QHBoxLayout

from .qstate_block import QStateBlock
from .qsymexec_graph import QSymExecGraph

log = logging.getLogger(__name__)


class QPathTree(QFrame):
    def __init__(self, simgr, state, symexec_view, workspace, parent=None):
        super().__init__(parent=parent)

        self.symexec_view = symexec_view
        self.workspace = workspace
        self.simgr = simgr
        self.state = state

        # widgets
        self._graph = None

        self._init_widgets()

        self.simgr.am_subscribe(self._watch_simgr)

    #
    # Public methods
    #

    def reload(self):
        if self.simgr.am_none:
            return

        states = [state for (stash, states) in self.simgr.stashes.items() if stash != "pruned" for state in states]
        hierarchy = self.simgr._hierarchy

        graph = self._generate_graph([state.history for state in states], hierarchy, self.symexec_view)

        self._graph.graph = graph

    #
    # Initialization
    #

    def _init_widgets(self):
        graph = QSymExecGraph(self.state, self.workspace, self.symexec_view, parent=self)

        self._graph = graph

        layout = QHBoxLayout()
        layout.addWidget(graph)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    #
    # Overriden methods
    #

    def sizeHint(self):
        return QSize(500, 500)

    #
    # Private methods
    #

    @staticmethod
    def _all_paths(paths, hierarchy):
        work = set(paths)
        seen = set()
        while len(work) > 0:
            path = work.pop()
            # print(path.path_id)
            if not hierarchy.history_contains(path.history) or len(hierarchy.history_successors(path.history)) == 0:
                if path.path_id not in seen:
                    yield path
                    seen.add(path.path_id)
            # get parents
            if hierarchy.history_contains(path.history):
                parents = hierarchy.history_predecessors(path.history)
                for parent_history in parents:
                    # assume _path_mapping always has the path
                    parent_path = hierarchy._path_mapping[parent_history]
                    work.add(parent_path)
                    if len(hierarchy.history_successors(parent_history)) > 1 and parent_path.path_id not in seen:
                        yield parent_path
                        seen.add(parent_path.path_id)

    @staticmethod
    def _all_edges_gen(state_histories, hierarchy):
        # TODO: reduce duplication with above function
        work = set(state_histories)
        while len(work) > 0:
            working_history = bot_history = work.pop()
            while hierarchy.history_contains(working_history):
                parent_histories = hierarchy.history_predecessors(working_history)
                if not parent_histories:
                    break

                parent_history = parent_histories[0]

                try:
                    successors = hierarchy.history_successors(parent_history)
                    if len(successors) > 1:
                        yield (parent_history, bot_history)
                        work.add(parent_history)
                        break
                    else:
                        working_history = parent_history
                except KeyError:
                    # the parent history is not found in the path mapping
                    log.error("Parent history %s is not found", parent_history)
                    break

    @staticmethod
    def _generate_graph(state_histories, hierarchy, symexec_view):
        g = networkx.DiGraph()

        history_to_block = {}

        for state_history in state_histories:
            if state_history not in history_to_block:
                history_to_block[state_history] = QStateBlock(False, symexec_view, history=state_history)
            g.add_node(history_to_block[state_history])

        for src, dst in QPathTree._all_edges_gen(state_histories, hierarchy):
            if src not in history_to_block:
                history_to_block[src] = QStateBlock(False, symexec_view, history=src)
            if dst not in history_to_block:
                history_to_block[dst] = QStateBlock(dst, False, symexec_view, history=dst)
            g.add_edge(history_to_block[src], history_to_block[dst])

        return g

    def _watch_simgr(self, **kwargs):
        self.reload()
