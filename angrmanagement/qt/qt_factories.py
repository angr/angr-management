
from enaml.qt.qt_factories import QT_FACTORIES

def qt_graph():
    from .qt_graph import QtGraph
    return QtGraph

def qt_flow_graph():
    from .qt_flow_graph import QtFlowGraph
    return QtFlowGraph

def qt_rich_label():
    from .qt_rich_label import QtRichLabel
    return QtRichLabel

def qt_rich_container():
    from .qt_rich_container import QtRichContainer
    return QtRichContainer

def qt_rich_field():
    from .qt_rich_field import QtRichField
    return QtRichField

# Inject into QT_FACTORIES

QT_FACTORIES['Graph'] = qt_graph
QT_FACTORIES['FlowGraph'] = qt_flow_graph
QT_FACTORIES['RichLabel'] = qt_rich_label
QT_FACTORIES['RichContainer'] = qt_rich_container
QT_FACTORIES['RichField'] = qt_rich_field
