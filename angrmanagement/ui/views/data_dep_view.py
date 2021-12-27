from typing import Optional, Dict, List, TYPE_CHECKING

from PySide2 import QtCore, QtWidgets
import logging

from angr.analyses.data_dependency import BaseDepNode, MemDepNode, VarDepNode, ConstantDepNode
from .view import BaseView
from ..widgets.qproximity_graph import QProximityGraph
from ..widgets.qproximitygraph_block import QProximityGraphBlock

_l = logging.getLogger(__name__)

if TYPE_CHECKING:
    from networkx import DiGraph
    from angr.analyses.data_dependency import DataDependencyGraphAnalysis
    from angr import SimState


class DataDepView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('data_dependency', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Data Dependency'
        self.workspace = workspace

        self._end_state: Optional['SimState'] = None
        self._start_addr: Optional[int] = None
        self._end_addr: Optional[int] = None
        self._block_addrs: Optional[List[int]] = None

        # UI widgets
        self._graph_widget: Optional[QProximityGraph] = None

        # Data
        self._data_dep_graph: Optional['DiGraph'] = None
        self._graph: Optional['DiGraph'] = None

    @property
    def analysis_params(self) -> dict:
        return {
            'end_state': self._end_state,
            'start_addr': self._start_addr,
            'end_addr': self._end_addr,
            'block_addrs': self._block_addrs
        }

    @analysis_params.setter
    def analysis_params(self, new_params: dict):
        if new_params == self.analysis_params:
            # Nothing new, no need to rerun analysis
            return

        try:
            self._end_state = new_params['end_state']
            self._start_addr = new_params['start_addr']
            self._end_addr = new_params['end_addr']
            self._block_addrs = new_params['block_addrs']

            self.run_analysis()
        except KeyError:
            _l.error("Unable to generate data dependency graph with provided parameters!")

    def run_analysis(self):
        inst = self.workspace.instance

        data_dep: 'DataDependencyGraphAnalysis' = inst.project.analyses.DataDep(
            self._end_state,
            self._start_addr,
            self._end_addr,
            self._block_addrs,
        )

        self._data_dep_graph = data_dep.graph
        self.reload()

    def reload(self):
        if self._graph_widget is None:
            return

        # Re-Generate the graph
        if not self._data_dep_graph:
            self._graph = None
            self._graph_widget.graph = None
            self._graph_widget.request_relayout()
            return

        self._graph = self._create_ui_graph()
        self._graph_widget.graph = self._graph

    def redraw_graph(self):
        if self._graph_widget.graph is not None:
            self._graph_widget.viewport().update()

    def sizeHint(self):
        return QtCore.QSize(400, 800)

    def _init_widgets(self):
        self._graph_widget = QProximityGraph(self.workspace, self)

        h_layout = QtWidgets.QHBoxLayout(self)
        h_layout.addWidget(self._graph_widget)
        h_layout.setContentsMargins(0, 0, 0, 0)

    def _register_events(self):
        self.workspace.current_screen.am_subscribe(self._on_screen_changed)
