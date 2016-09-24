
from enaml.qt.qt_factories import QT_FACTORIES

def qt_graph():
    from .qt_graph import QtGraph
    return QtGraph

def qt_flow_graph():
    from .qt_flow_graph import QtFlowGraph
    return QtFlowGraph

def rich_label():
    from .qt_rich_label import QtRichLabel
    return QtRichLabel

# Inject into QT_FACTORIES

QT_FACTORIES['RichLabel'] = rich_label
QT_FACTORIES['Graph'] = qt_graph
QT_FACTORIES['FlowGraph'] = qt_flow_graph
