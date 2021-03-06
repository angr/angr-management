from typing import TYPE_CHECKING

from PySide2.QtCore import Qt, QEvent
from PySide2.QtGui import QTextCharFormat
from PySide2.QtWidgets import QMenu, QAction

from pyqodeng.core import api
from pyqodeng.core import modes
from pyqodeng.core import panels

from angr.analyses.decompiler.structured_codegen import CBinaryOp, CVariable, CFunctionCall, CFunction

from ..dialogs.rename_node import RenameNode
from ..widgets.qccode_highlighter import QCCodeHighlighter
from ..menus.menu import Menu

if TYPE_CHECKING:
    from ..documents.qcodedocument import QCodeDocument
    from ..views.code_view import CodeView


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

        self._code_view: 'CodeView' = code_view

        self.panels.append(panels.LineNumberPanel())
        self.panels.append(panels.FoldingPanel())

        self.modes.append(modes.SymbolMatcherMode())

        self.setTabChangesFocus(False)
        self.setReadOnly(True)

        self.constant_actions = [ ]
        self.operator_actions = [ ]
        self.variable_actions = [ ]
        self.selected_actions = [ ]
        self.call_actions = [ ]
        self.default_actions = [ ]
        self.function_name_actions = []
        self._initialize_context_menus()

        self._selected_node = None

        self.action_rename_node = None

        # but we don't need some of the actions
        self.remove_action(self.action_undo)
        self.remove_action(self.action_redo)
        self.remove_action(self.action_cut)
        self.remove_action(self.action_paste)
        self.remove_action(self.action_duplicate_line)
        self.remove_action(self.action_swap_line_up)
        self.remove_action(self.action_swap_line_down)

    def node_under_cursor(self):
        doc: 'QCodeDocument' = self.document()
        # determine the current status
        cursor = self.textCursor()
        pos = cursor.position()
        current_node = doc.get_node_at_position(pos)
        if current_node is not None:
            return current_node
        else:
            # nothing is under the cursor
            return None

    def get_context_menu(self):
        if self.document() is None:
            return QMenu()

        # TODO: Anything in sel?

        # Get the highlighted item
        under_cursor = self.node_under_cursor()

        mnu = QMenu()
        self._selected_node = None
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
        if isinstance(under_cursor, CVariable):
            # variable in selection
            self._selected_node = under_cursor
            mnu.addActions(self.variable_actions)
        if isinstance(under_cursor, CFunction):
            # decompiled function name in selection
            self._selected_node = under_cursor
            mnu.addActions(self.function_name_actions)
            for entry in self.workspace.plugins.build_context_menu_function(self.workspace.instance.kb.functions[under_cursor.name]):
                Menu.translate_element(mnu, entry)
        else:
            mnu.addActions(self.default_actions)

        for entry in self.workspace.plugins.build_context_menu_node(under_cursor):
            Menu.translate_element(mnu, entry)

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

    def get_src_to_inst(self) -> int:
        """
        Uses the current cursor position, which is in a code view, and gets the
        corresponding instruction address that is associated to the code.
        Returns the start of the function if unable to calculate.

        :return: int (address of inst)
        """

        # get the Qt document
        doc: 'QCodeDocument' = self.document()

        # get the current position of the cursor
        cursor = self.textCursor()
        pos = cursor.position()

        # get the node at the associated cursor position
        current_node = doc.get_stmt_node_at_position(pos)

        if current_node is not None and hasattr(current_node, 'tags') and \
                current_node.tags is not None and 'ins_addr' in current_node.tags:
            asm_ins_addr = current_node.tags['ins_addr']

        else:
            # the top of the function decompiled
            asm_ins_addr = self._code_view.function.addr

        return asm_ins_addr

    def keyReleaseEvent(self, event):
        key = event.key()
        if key == Qt.Key_Tab:
            # Compute the location to switch back to
            asm_inst_addr = self.get_src_to_inst()

            # Switch back to disassembly view
            self.workspace.jump_to(asm_inst_addr)
            return True
        elif key == Qt.Key_N:
            node = self.node_under_cursor()
            if isinstance(node, (CVariable, CFunction)):
                self.rename_node(node)
            return True

        return super().keyPressEvent(event)

    def setDocument(self, document):
        super().setDocument(document)

        self.modes.append(QCCodeHighlighter(self.document(), color_scheme=ColorSchemeIDA()))
        self.syntax_highlighter.fold_detector = api.CharBasedFoldDetector()

    #
    # Actions
    #

    def rename_node(self, node=None):
        n = node if node is not None else self._selected_node
        if not isinstance(n, (CVariable, CFunction)):
            return
        dialog = RenameNode(code_view=self._code_view, node=n)
        dialog.exec_()

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

        self.action_rename_node = QAction('Re&name variable', self)
        self.action_rename_node.triggered.connect(self.rename_node)

        self.variable_actions = [
            self.action_rename_node,
        ]

        self.function_name_actions = [
            self.action_rename_node,
        ]

        self.constant_actions += base_actions
        self.operator_actions += base_actions
        self.variable_actions += base_actions
        self.function_name_actions += base_actions
        self.call_actions += base_actions
        self.selected_actions += base_actions
        self.default_actions += base_actions
