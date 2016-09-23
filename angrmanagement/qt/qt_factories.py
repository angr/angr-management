
from enaml.qt.qt_factories import QT_FACTORIES

def rich_label():
    from .qt_rich_label import QtRichLabel
    return QtRichLabel

# Inject into QT_FACTORIES

QT_FACTORIES['RichLabel'] = rich_label
