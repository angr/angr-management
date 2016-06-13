
from enaml.qt.qt_factories import QT_FACTORIES

from .graph import Graph, QtGraph
from .flowgraph import FlowGraph, QtFlowGraph
from .utils import to_supergraph


QT_FACTORIES['Graph'] = lambda: QtGraph
QT_FACTORIES['FlowGraph'] = lambda: QtFlowGraph