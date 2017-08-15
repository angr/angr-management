
import logging

import networkx
from PySide.QtGui import QFrame, QHBoxLayout
from PySide.QtCore import QSize

from .qsymexec_graph import QSymExecGraph
from .qstate_block import QStateBlock


l = logging.getLogger('ui.widgets.qpathtree')


class QPathTree(QFrame):
    def __init__(self, symexec_view, workspace, parent=None):
        super(QPathTree, self).__init__(parent=parent)

        self._symexec_view = symexec_view
        self.workspace = workspace

        self._simgr = None

        # widgets
        self._graph = None

        self._init_widgets()

    #
    # Properties
    #

    @property
    def simgr(self):
        return self._simgr

    @simgr.setter
    def simgr(self, v):
        self._simgr = v
        self.reload()

    @property
    def symexec_view(self):
        return self._symexec_view

    #
    # Public methods
    #

    def reload(self):

        states = [ state for (stash, states) in self.simgr.stashes.items() if stash != 'pruned' for state in states ]
        hierarchy = self.simgr._hierarchy

        graph = self._generate_graph(states, hierarchy, self.symexec_view)

        self._graph.graph = graph

    #
    # Initialization
    #

    def _init_widgets(self):

        graph = QSymExecGraph(self.workspace, parent=self)

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
            # print path.path_id
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
                    if len(hierarchy.history_successors(parent_history)) > 1:
                        if parent_path.path_id not in seen:
                            yield parent_path
                            seen.add(parent_path.path_id)

    @staticmethod
    def _all_edges_gen(paths, hierarchy):
        # TODO: reduce duplication with above function
        work = set(paths)
        # __import__('ipdb').set_trace()
        while len(work) > 0:
            working_path = bot_path = work.pop()
            while hierarchy.history_contains(working_path.history):
                parent_histories = hierarchy.history_predecessors(working_path.history)
                if not parent_histories:
                    break

                parent_history = parent_histories[0]
                # assume _path_mapping always has the path
                try:
                    parent_path = hierarchy._path_mapping[parent_history]
                    if len(hierarchy.history_successors(parent_path.history)) > 1:
                        yield (parent_path, bot_path)
                        work.add(parent_path)
                        break
                    else:
                        working_path = parent_path
                except KeyError:
                    # the parent history is not found in the path mapping
                    l.error('Parent history %s is not found', parent_history)
                    break

    @staticmethod
    def _generate_graph(states, hierarchy, symexec_view):

        g = networkx.DiGraph()

        path_to_block = { }

        for state in states:
            if state not in path_to_block:
                path_to_block[state] = QStateBlock(state, False, symexec_view)
            g.add_node(path_to_block[state])

        for src, dst in QPathTree._all_edges_gen(states, hierarchy):
            if src not in path_to_block:
                path_to_block[src] = QStateBlock(src, False, symexec_view)
            if dst not in path_to_block:
                path_to_block[dst] = QStateBlock(dst, False, symexec_view)
            g.add_edge(path_to_block[src], path_to_block[dst])

        return g
