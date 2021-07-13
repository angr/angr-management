from typing import TYPE_CHECKING

from PySide2.QtCore import Qt, QEvent
from PySide2.QtGui import QTextCharFormat
from PySide2.QtWidgets import QMenu, QAction, QInputDialog, QLineEdit, QApplication

from pyqodeng.core import api
from pyqodeng.core import modes
from pyqodeng.core import panels

from angr.sim_variable import SimVariable, SimTemporaryVariable
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable, CFunctionCall, CFunction, CStructField

from ..documents.qcodedocument import QCodeDocument
from ..dialogs.rename_node import RenameNode
from ..widgets.qccode_highlighter import QCCodeHighlighter
from ..menus.menu import Menu

if TYPE_CHECKING:
    from PySide2.QtGui import QTextDocument
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
    """
    A subclass of pyqodeng's CodeEdit, specialized to handle the kinds of textual interaction expected of the pseudocode
    view. You will typically interact with this class as code_view.textedit.
    """
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
        self.action_rename_node = None
        self._selected_node = None

        self._initialize_context_menus()

        # but we don't need some of the actions
        self.remove_action(self.action_undo)
        self.remove_action(self.action_redo)
        self.remove_action(self.action_cut)
        self.remove_action(self.action_paste)
        self.remove_action(self.action_duplicate_line)
        self.remove_action(self.action_swap_line_up)
        self.remove_action(self.action_swap_line_down)

    def node_under_cursor(self):
        doc: 'QTextDocument' = self.document()
        if not isinstance(doc, QCodeDocument):
            # this is not the qcodedocument that the decompiler generates. this means the pseudocode view is empty
            return None

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
            for entry in self.workspace.plugins.build_context_menu_functions(
                    [self.workspace.instance.kb.functions[under_cursor.name]]):
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
        Reimplemented to capture the Tab key pressed/released event.

        :param event:
        :return:
        """

        if event.type() == QEvent.ShortcutOverride and event.key() == Qt.Key_Tab:
            event.accept()
            return True
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            return self.keyPressEvent(event)

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

    def keyPressEvent(self, event):
        key = event.key()
        node = self.node_under_cursor()

        if key == Qt.Key_N:
            if isinstance(node, (CVariable, CFunction, CFunctionCall, CStructField)):
                self.rename_node(node=node)
            return True
        if key in (Qt.Key_Slash, Qt.Key_Question):
            self.comment(expr=event.modifiers() & Qt.ShiftModifier == Qt.ShiftModifier)
            return True
        if key == Qt.Key_Minus and QApplication.keyboardModifiers() & Qt.CTRL != 0:
            self.zoomOut()
        if key == Qt.Key_Equal and QApplication.keyboardModifiers() & Qt.CTRL != 0:
            self.zoomIn()

        if self._code_view.keyPressEvent(event):
            return True

        saved_mode = self.textInteractionFlags()
        if key in (Qt.Key_Left, Qt.Key_Right, Qt.Key_Up, Qt.Key_Down,
                   Qt.Key_PageDown, Qt.Key_PageUp, Qt.Key_Home, Qt.Key_End):
            self.setTextInteractionFlags(saved_mode | Qt.TextEditable)
        result = super().keyPressEvent(event)
        self.setTextInteractionFlags(saved_mode)
        return result

    def paintEvent(self, e):
        saved_mode = self.textInteractionFlags()
        self.setTextInteractionFlags(saved_mode | Qt.TextEditable)
        super().paintEvent(e)
        self.setTextInteractionFlags(saved_mode)

    def setDocument(self, document):
        super().setDocument(document)

        self.modes.append(QCCodeHighlighter(self.document(), color_scheme=ColorSchemeIDA()))
        self.syntax_highlighter.fold_detector = api.CharBasedFoldDetector()

    #
    # Actions
    #

    def rename_node(self, *args, node=None):  # pylint: disable=unused-argument
        n = node if node is not None else self._selected_node
        if not isinstance(n, (CVariable, CFunction, CFunctionCall, CStructField)):
            return
        if isinstance(n, CVariable) and isinstance(n.variable, SimTemporaryVariable):
            # unsupported right now..
            return
        dialog = RenameNode(code_view=self._code_view, node=n)
        dialog.exec_()

    def comment(self, expr=False, node=None):
        addr = (getattr(node, 'tags', None) or {}).get('ins_addr', None)
        if addr is None:
            if expr:
                addr = self.get_src_to_inst()
            else:
                pos = self.textCursor().position()
                while self.document().characterAt(pos) not in ('\n', '\u2029') and \
                        pos < self.document().characterCount():  # qt WHAT are you doing
                    pos += 1
                node = self.document().get_stmt_node_at_position(pos)
                addr = (getattr(node, 'tags', None) or {}).get('ins_addr', None)

        if addr is None:
            return

        try:
            cdict = self._code_view.codegen.expr_comments if expr else self._code_view.codegen.stmt_comments
        except AttributeError:
            return
        text = cdict.get(addr, "")

        text, ok = QInputDialog.getText(
            self._code_view,
            "Expression Comment" if expr else "Statement Comment",
            "",
            QLineEdit.Normal,
            text)

        if ok:
            exists = addr in cdict
            if text:
                # callback
                self.workspace.plugins.handle_comment_changed(addr, text, not exists, True)
                cdict[addr] = text
            else:
                if exists:
                    # callback
                    self.workspace.plugins.handle_comment_changed(addr, "", False, True)
                    del cdict[addr]

            self._code_view.codegen.am_event()

    def toggle_struct(self):
        node = self._selected_node
        if not isinstance(node, CVariable):
            return
        if isinstance(node.variable, SimVariable):
            ident = node.variable.ident
            if ident in self._code_view.vars_must_struct:
                self._code_view.vars_must_struct.remove(ident)
            else:
                self._code_view.vars_must_struct.add(ident)
            # decompile again
            self._code_view.decompile()

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
        self.action_toggle_struct = QAction('Toggle &struct/array')
        self.action_toggle_struct.triggered.connect(self.toggle_struct)

        self.variable_actions = [
            self.action_rename_node,
            self.action_toggle_struct,
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
