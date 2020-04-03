
from PySide2.QtCore import Qt, QEvent
from PySide2.QtGui import QTextCharFormat
from pygments.lexers.compiled import CLexer
from pyqodeng.core import api
from pyqodeng.core import modes
from pyqodeng.core import panels

from ..widgets.qccode_highlighter import QCCodeHighlighter


class ColorSchemeIDA(api.ColorScheme):
    """
    An IDA-like color scheme.
    """
    def __init__(self):
        super().__init__('default')

        # override existing formats
        function_format = QTextCharFormat()
        function_format.setForeground(self._get_brush("0000ff"))
        self.formats['function'] = function_format


class QCCodeEdit(api.CodeEdit):
    def __init__(self, code_view):
        super().__init__()

        self._code_view = code_view

        self.panels.append(panels.LineNumberPanel())
        self.panels.append(panels.FoldingPanel())

        self.modes.append(modes.SymbolMatcherMode())

        self.setTabChangesFocus(False)
        self.setReadOnly(True)

    @property
    def workspace(self):
        return self._code_view.workspace if self._code_view is not None else None

    def event(self, event):
        """
        Reimplemented to capture the Tab key pressed event.

        :param event:
        :return:
        """

        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.keyPressEvent(event)
            return True

        return super().event(event)

    def keyPressEvent(self, key_event):
        key = key_event.key()
        if key == Qt.Key_Tab:
            # Switch back to disassembly view
            self.workspace.jump_to(self._code_view.function.addr)
            return True

        super().keyPressEvent(key_event)

    def setDocument(self, document):
        super().setDocument(document)

        self.modes.append(QCCodeHighlighter(self.document(), color_scheme=ColorSchemeIDA()))
        self.syntax_highlighter.fold_detector = api.CharBasedFoldDetector()
