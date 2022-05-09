from typing import TYPE_CHECKING

from PySide2.QtCore import Qt, QEvent
from PySide2.QtGui import QTextCharFormat, QKeySequence
from PySide2.QtWidgets import QMenu, QAction, QInputDialog, QLineEdit, QApplication, QShortcut

from pyqodeng.core import api
from pyqodeng.core import modes
from pyqodeng.core import panels

from ailment.statement import Store, Assignment
from ailment.expression import Load, Convert
from angr.sim_type import SimType
from angr.sim_variable import SimVariable, SimTemporaryVariable
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable, CFunctionCall, CFunction, \
    CStructField, CIndexedVariable, CVariableField, CUnaryOp, CConstant

from ..documents.qcodedocument import QCodeDocument
from ..dialogs.rename_node import RenameNode
from ..dialogs.retype_node import RetypeNode
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
        if isinstance(under_cursor, CConstant):
            self._selected_node = under_cursor
            mnu.addActions(self.constant_actions)
        if isinstance(under_cursor, (CBinaryOp, CUnaryOp)):
            # operator in selection
            self._selected_node = under_cursor
            mnu.addActions(self.operator_actions)
        if isinstance(under_cursor, CFunctionCall) \
                and "vex_block_addr" in under_cursor.tags \
                and "ins_addr" in under_cursor.tags:
            # function call in selection
            self._selected_node = under_cursor
            mnu.addActions(self.call_actions)
        if isinstance(under_cursor, (CVariable, CIndexedVariable, CVariableField, CStructField)):
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
        modifiers = event.modifiers()
        xkey = key
        if modifiers & Qt.ShiftModifier:
            xkey += Qt.SHIFT
        if modifiers & Qt.ControlModifier:
            xkey += Qt.CTRL
        if modifiers & Qt.AltModifier:
            xkey += Qt.ALT
        if modifiers & Qt.MetaModifier:
            xkey += Qt.META
        sequence = QKeySequence(xkey)
        mnu = self.get_context_menu()
        for item in mnu.actions():
            if item.shortcut().matches(sequence) == QKeySequence.SequenceMatch.ExactMatch:
                item.activate(QAction.ActionEvent.Trigger)
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
        if not isinstance(n, (CVariable, CFunction, CFunctionCall, CStructField, SimType)):
            return
        if isinstance(n, CVariable) and isinstance(n.variable, SimTemporaryVariable):
            # unsupported right now..
            return
        dialog = RenameNode(code_view=self._code_view, node=n)
        dialog.exec_()

    def retype_node(self, *args, node=None, node_type=None):  # pylint: disable=unused-argument
        if node is None:
            node = self._selected_node
        if not isinstance(node, (CVariable, CFunction, CFunctionCall, CStructField)):
            return
        if isinstance(node, CVariable) and isinstance(node.variable, SimTemporaryVariable):
            # unsupported right now..
            return
        dialog = RetypeNode(self.workspace.instance, code_view=self._code_view, node=node,
                            node_type=node_type, variable=node.variable)
        dialog.exec_()

        new_node_type = dialog.new_type
        if new_node_type is not None:
            if self._code_view is not None and node is not None:
                # need workspace for altering callbacks of changes
                workspace = self._code_view.workspace
                variable_kb = self._code_view.codegen._variable_kb
                # specify the type
                new_node_type = new_node_type.with_arch(workspace.instance.project.arch)
                variable_kb.variables[self._code_view.function.addr].variables_with_manual_types.add(node.variable)
                variable_kb.variables[self._code_view.function.addr].set_variable_type(node.variable, new_node_type)

                self._code_view.codegen.am_event(event="retype_variable", node=node, variable=node.variable)

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
                self.workspace.plugins.handle_comment_changed(addr, "", text, not exists, True)
                cdict[addr] = text
            else:
                if exists:
                    # callback
                    self.workspace.plugins.handle_comment_changed(addr, cdict[addr], "", False, True)
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

    def collapse_expr(self):
        if hasattr(self._selected_node, 'collapsed'):
            self._selected_node.collapsed = True
            self._code_view.codegen.am_event()

    def expand_expr(self):
        if hasattr(self._selected_node, 'collapsed'):
            self._selected_node.collapsed = False
            self._code_view.codegen.am_event()

    def hex_constant(self):
        if hasattr(self._selected_node, 'fmt_hex'):
            self._selected_node.fmt_hex ^= True
            self._code_view.codegen.am_event()

    def neg_constant(self):
        if hasattr(self._selected_node, 'fmt_neg'):
            self._selected_node.fmt_neg ^= True
            self._code_view.codegen.am_event()

    def expr2armasm(self):

        def _assemble(expr, expr_addr) -> str:
            return converter.assemble(expr, self._code_view.function.addr, expr_addr)

        node = self._selected_node
        # figure out where we are
        if not isinstance(node, (CVariable, CIndexedVariable, CVariableField, CStructField)):
            return

        doc: 'QCodeDocument' = self.document()
        cursor = self.textCursor()
        pos = cursor.position()
        current_node = doc.get_stmt_node_at_position(pos)

        if current_node is None:
            return

        ins_addr = current_node.tags.get("ins_addr", None)
        if ins_addr is None:
            return

        # traverse the stored clinic graph to find the AIL block
        cache = self.workspace.instance.kb.structured_code[(self._code_view.function.addr, "pseudocode")]
        the_node = None
        for node in cache.clinic.graph.nodes():
            if node.addr <= ins_addr < node.addr + node.original_size:
                the_node = node
                break

        if the_node is None:
            return

        converter = self.workspace.plugins.get_plugin_instance_by_name("AIL2ARM32")

        # I'm lazy - I'll get the first Load if available
        lst = [ ]
        for stmt in the_node.statements:
            if isinstance(stmt, Assignment):
                if isinstance(stmt.src, Load):
                    asm = _assemble(stmt.src, stmt.src.ins_addr)
                    lst.append((str(stmt), str(stmt.src), asm))
                elif isinstance(stmt.src, Convert) and isinstance(stmt.src.operand, Load):
                    asm = _assemble(stmt.src, stmt.src.operand.ins_addr)
                    lst.append((str(stmt), str(stmt.src), asm))
            elif isinstance(stmt, Store):
                if isinstance(stmt.data, Load):
                    asm = _assemble(stmt.data, stmt.data.ins_addr)
                    lst.append((str(stmt), str(stmt.data), asm))
                elif isinstance(stmt.data, Convert) and isinstance(stmt.data.operand, Load):
                    asm = _assemble(stmt.data, stmt.data.operand.ins_addr)
                    lst.append((str(stmt), str(stmt.data), asm))

        # format text
        text = f"The AIL block:\n{str(the_node)}\n\n"
        for stmt, expr, asm in lst:
            text += f"Statement: {stmt}\n"
            text += f"Expression: {expr}\n"
            text += f"Assembly:\n{asm}\n\n"

        converter.display_output(text)

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

        self.action_rename_node = QAction('Rename variable', self)
        self.action_rename_node.triggered.connect(self.rename_node)
        self.action_rename_node.setShortcut(QKeySequence('N'))
        self.action_retype_node = QAction("Retype variable", self)
        self.action_retype_node.triggered.connect(self.retype_node)
        self.action_retype_node.setShortcut(QKeySequence('Y'))
        self.action_toggle_struct = QAction('Toggle &struct/array')
        self.action_toggle_struct.triggered.connect(self.toggle_struct)
        self.action_collapse_expr = QAction('Collapse expression', self)
        self.action_collapse_expr.triggered.connect(self.collapse_expr)
        self.action_expand_expr = QAction('Expand expression', self)
        self.action_expand_expr.triggered.connect(self.expand_expr)
        self.action_hex = QAction('Toggle hex', self)
        self.action_hex.triggered.connect(self.hex_constant)
        self.action_hex.setShortcut(QKeySequence('H'))
        self.action_neg = QAction('Toggle negative', self)
        self.action_neg.triggered.connect(self.neg_constant)
        self.action_neg.setShortcut(QKeySequence('_'))

        expr_actions = [
            self.action_collapse_expr,
            self.action_expand_expr,
        ]

        self.action_asmgen = QAction("Expression -> ARM THUMB assembly...")
        self.action_asmgen.triggered.connect(self.expr2armasm)

        self.variable_actions = [
            self.action_rename_node,
            self.action_retype_node,
            self.action_toggle_struct,
            self.action_asmgen,
        ]

        self.function_name_actions = [
            self.action_rename_node,
        ]

        self.constant_actions = [
            self.action_hex,
            self.action_neg,
        ]

        self.constant_actions += base_actions + expr_actions
        self.operator_actions += base_actions + expr_actions
        self.variable_actions += base_actions + expr_actions
        self.function_name_actions += base_actions
        self.call_actions += base_actions + expr_actions
        self.selected_actions += base_actions
        self.default_actions += base_actions
