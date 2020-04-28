
from PySide2.QtCore import Qt, QEvent
from PySide2.QtGui import QTextCharFormat
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
        super().__init__(create_default_actions=True)

        self._code_view = code_view

        self.panels.append(panels.LineNumberPanel())
        self.panels.append(panels.FoldingPanel())

        self.modes.append(modes.SymbolMatcherMode())

        self.setTabChangesFocus(False)
        self.setReadOnly(True)

        # but we don't need some of the actions
        self.remove_action(self.action_undo)
        self.remove_action(self.action_redo)
        self.remove_action(self.action_cut)
        self.remove_action(self.action_paste)
        self.remove_action(self.action_duplicate_line)
        self.remove_action(self.action_swap_line_up)
        self.remove_action(self.action_swap_line_down)

    @property
    def workspace(self):
        return self._code_view.workspace if self._code_view is not None else None

    def event(self, event):
        """
        Reimplemented to capture the Tab key pressed event.

        :param event:
        :return:
        """

        if event.type() == QEvent.KeyRelease and event.key() == Qt.Key_Tab:
            self.keyReleaseEvent(event)
            return True

        return super().event(event)

    def keyReleaseEvent(self, key_event):
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
