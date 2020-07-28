from typing import TYPE_CHECKING

from PySide2.QtCore import Qt, QEvent
from PySide2.QtGui import QTextCharFormat
from PySide2.QtWidgets import QMenu, QAction

from pyqodeng.core import api
from pyqodeng.core import modes
from pyqodeng.core import panels

import pyvex
from angr.analyses.decompiler.structured_codegen import CBinaryOp, CFunctionCall

from ..widgets.qccode_highlighter import QCCodeHighlighter

if TYPE_CHECKING:
    from ..documents.qcodedocument import QCodeDocument


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

        self.constant_actions = [ ]
        self.operator_actions = [ ]
        self.selected_actions = [ ]
        self.call_actions = [ ]
        self.default_actions = [ ]
        self._initialize_context_menus()

        self._selected_node = None

        # but we don't need some of the actions
        self.remove_action(self.action_undo)
        self.remove_action(self.action_redo)
        self.remove_action(self.action_cut)
        self.remove_action(self.action_paste)
        self.remove_action(self.action_duplicate_line)
        self.remove_action(self.action_swap_line_up)
        self.remove_action(self.action_swap_line_down)

    def get_context_menu(self):
        if self.document() is None:
            return QMenu()

        doc: 'QCodeDocument' = self.document()
        # determine the current status
        cursor = self.textCursor()
        pos = cursor.position()
        current_node = doc.get_node_at_position(pos)
        if current_node is not None:
            under_cursor = current_node
        else:
            # nothing is under the cursor
            under_cursor = None

        # TODO: Anything in sel?

        # Get the highlighted item

        mnu = QMenu()
        if isinstance(under_cursor, CBinaryOp) \
                and "vex_stmt_idx" in under_cursor.tags \
                and "vex_block_addr" in under_cursor.tags:
            # operator in selection
            self._selected_node = under_cursor
            mnu.addActions(self.operator_actions)
        if isinstance(under_cursor, CFunctionCall) \
                and "vex_block_addr" in under_cursor.tags \
                and "ins_addr" in under_cursor.tags:
            # function call in selection
            self._selected_node = under_cursor
            mnu.addActions(self.call_actions)
        else:
            mnu.addActions(self.default_actions)

        return mnu

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

    @staticmethod
    def _separator():
        sep = QAction()
        sep.setSeparator(True)
        return sep

    def _initialize_context_menus(self):

        base_actions = [
            self._separator(),
            self.action_copy,
            self.action_select_all,
        ]

        self.constant_actions += base_actions
        self.operator_actions += base_actions
        self.call_actions += base_actions
        self.selected_actions += base_actions
        self.default_actions += base_actions
