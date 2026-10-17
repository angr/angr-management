from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen import (
    FunctionCallNode,
    FunctionNode,
    StructFieldNode,
    VariableNode,
)
from angr.sim_type import SimType
from angr.sim_variable import SimTemporaryVariable
from pyqodeng.core import api, modes, panels
from pyqodeng.core.api.syntax_highlighter import COLOR_SCHEME_KEYS
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import QApplication, QInputDialog, QLineEdit, QMenu

from angrmanagement.present.menus import Menu, MenuEntry, MenuSeparator
from angrmanagement.ui.dialogs.rename_node import RenameNode
from angrmanagement.ui.dialogs.retype_node import RetypeNode
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.documents.qcodedocument import QCodeDocument
from angrmanagement.ui.views.pattern_view import PatternView
from angrmanagement.ui.widgets.qccode_highlighter import FORMATS, QCCodeHighlighter
from angrmanagement.ui.widgets.qinline_comment_editor import QInlineCommentEditor
from angrmanagement.ui.widgets.qnode_tip import QNodeTip

if TYPE_CHECKING:
    from angr.sim_type import SimTypeFunction
    from PySide6.QtGui import QTextDocument

    from angrmanagement.present.code import CodePresenter
    from angrmanagement.ui.views.code_view import CodeView


_l = logging.getLogger(__name__)


class ColorSchemeIDA(api.ColorScheme):
    """
    An IDA-like color scheme.
    """

    def __init__(self) -> None:
        super().__init__("default")
        for k, v in FORMATS.items():
            if k in COLOR_SCHEME_KEYS:
                self.formats[COLOR_SCHEME_KEYS[k]] = v
                self.formats[k] = v


class QCCodeEdit(api.CodeEdit):
    """
    A subclass of pyqodeng's CodeEdit, specialized to handle the kinds of textual interaction expected of the pseudocode
    view. You will typically interact with this class as code_view.textedit.
    """

    def __init__(self, code_view) -> None:
        self._palette_updating = False
        self.line_number_panel: panels.LineNumberPanel | None = None
        self.folding_panel: panels.FoldingPanel | None = None
        self.code_highlighter: QCCodeHighlighter | None = None
        self.color_scheme: api.ColorScheme | None = None

        super().__init__(create_default_actions=True)
        self._code_view: CodeView = code_view
        self.create_panels()

        self.modes.append(modes.SymbolMatcherMode())

        self.setTabChangesFocus(False)
        self.setReadOnly(True)

        self._node_tip = QNodeTip(self)

        self.constant_actions = []
        self.operator_actions = []
        self.variable_actions = []
        self.call_actions = []
        self.default_actions = []
        self.function_name_actions = []
        self.action_rename_node = None
        self.action_xref = None
        self._selected_node = None
        self._inline_comment_editor: QInlineCommentEditor | None = None

        self.mouse_moved.connect(self._on_hover_mouse_moved)

        self._initialize_context_menus()

        # but we don't need some of the actions
        self.remove_action(self.action_undo)
        self.remove_action(self.action_redo)
        self.remove_action(self.action_cut)
        self.remove_action(self.action_paste)
        self.remove_action(self.action_duplicate_line)
        self.remove_action(self.action_swap_line_up)
        self.remove_action(self.action_swap_line_down)

    def create_panels(self):
        self.line_number_panel = panels.LineNumberPanel()
        self.folding_panel = panels.FoldingPanel()
        self.panels.append(self.line_number_panel)
        self.panels.append(self.folding_panel)
        self.line_number_panel.setVisible(True)
        self.folding_panel.setVisible(True)

    def remove_panels(self):
        if self.line_number_panel is not None:
            self.line_number_panel.setVisible(False)
            self.panels.remove(self.line_number_panel.name)
            self.line_number_panel = None
        if self.folding_panel is not None:
            self.folding_panel.setVisible(False)
            self.panels.remove(self.folding_panel.name)
            self.folding_panel = None

    def node_under_cursor(self):
        doc: QTextDocument = self.document()
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

        # what the menu holds for the node comes from the presenter; each entry's key names one of the actions here
        menu = self.presenter.context_menu(node=under_cursor)
        self._selected_node = self.presenter.selected_node
        mnu = QMenu()
        if menu is None:
            return mnu
        for entry in menu.items():
            action = getattr(self, entry.key, None) if isinstance(entry, MenuEntry) and entry.key else None
            if action is not None:
                mnu.addAction(action)
            elif isinstance(entry, MenuSeparator):
                mnu.addSeparator()
            else:
                # the plugins' entries
                Menu.translate_element(mnu, entry)
        return mnu

    @property
    def presenter(self) -> CodePresenter:
        return self._code_view.presenter

    @property
    def workspace(self):
        return self._code_view.workspace if self._code_view is not None else None

    @property
    def instance(self):
        return self._code_view.instance if self._code_view is not None else None

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

    def get_closest_insaddr(self, node, expr=None) -> int | None:
        return self.presenter.closest_insaddr(node, expr=bool(expr), pos=self.textCursor().position())

    def get_src_to_inst(self) -> int:
        """
        Uses the current cursor position, which is in a code view, and gets the
        corresponding instruction address that is associated to the code.
        Returns the start of the function if unable to calculate.

        :return: int (address of inst)
        """
        return self.presenter.src_to_inst(self.textCursor().position())

    def keyPressEvent(self, event):
        self._dismiss_nodetip()
        key = event.key()
        modifiers = event.modifiers()
        xkey = key
        if isinstance(xkey, int):
            xkey = Qt.Key(xkey)
        if modifiers & Qt.ShiftModifier:
            xkey |= Qt.Key.Key_Shift
        if modifiers & Qt.ControlModifier:
            xkey |= Qt.Key.Key_Control
        if modifiers & Qt.AltModifier:
            xkey |= Qt.Key.Key_Alt
        if modifiers & Qt.MetaModifier:
            xkey |= Qt.Key.Key_Meta
        sequence = QKeySequence(xkey)
        mnu = self.get_context_menu()
        for item in mnu.actions():
            if item.shortcut().matches(sequence) == QKeySequence.SequenceMatch.ExactMatch:
                item.activate(QAction.ActionEvent.Trigger)
                return True

        if key in (Qt.Key_Slash, Qt.Key_Question, Qt.Key_Semicolon):
            self.comment(
                expr=event.modifiers() & Qt.KeyboardModifier.ShiftModifier == Qt.KeyboardModifier.ShiftModifier
            )
            return True
        if key == Qt.Key_Colon:
            # Shift+; -- the multi-line-capable dialog
            self.comment(inline=False)
            return True
        if key == Qt.Key_Minus and QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier != 0:
            self.zoomOut()
        if key == Qt.Key_Equal and QApplication.keyboardModifiers() & Qt.KeyboardModifier.ControlModifier != 0:
            self.zoomIn()

        if self._code_view.keyPressEvent(event):
            return True

        saved_mode = self.textInteractionFlags()
        if key in (
            Qt.Key.Key_Left,
            Qt.Key.Key_Right,
            Qt.Key.Key_Up,
            Qt.Key.Key_Down,
            Qt.Key.Key_PageDown,
            Qt.Key.Key_PageUp,
            Qt.Key.Key_Home,
            Qt.Key.Key_End,
        ):
            self.setTextInteractionFlags(saved_mode | Qt.TextInteractionFlag.TextEditable)
        result = super().keyPressEvent(event)  # pylint:disable=assignment-from-none
        self.setTextInteractionFlags(saved_mode)
        return result

    def paintEvent(self, e) -> None:
        saved_mode = self.textInteractionFlags()
        self.setTextInteractionFlags(saved_mode | Qt.TextInteractionFlag.TextEditable)
        super().paintEvent(e)
        self.setTextInteractionFlags(saved_mode)

    def setDocument(self, document) -> None:
        super().setDocument(document)

        self.color_scheme = ColorSchemeIDA()
        self.code_highlighter = QCCodeHighlighter(
            self.document(), color_scheme=self.color_scheme, flavor=self._code_view.flavor
        )
        self.modes.append(self.code_highlighter)
        self.syntax_highlighter.fold_detector = api.CharBasedFoldDetector()

    def setPalette(self, palette, **kwargs) -> None:
        super().setPalette(palette, **kwargs)
        if self._palette_updating:
            return
        self._palette_updating = True
        # re-create panels to apply the new palette
        self.remove_panels()
        self.create_panels()

        if hasattr(self, "_node_tip") and self._node_tip is not None:
            self._node_tip.refresh_palette()

        # re-generate color scheme because FORMATS has changed
        if self.color_scheme is not None:
            self.color_scheme = ColorSchemeIDA()
        if self.code_highlighter is not None:
            self.code_highlighter.refresh_editor(self.color_scheme)
            self.rehighlight()
        self._palette_updating = False

    def _on_hover_mouse_moved(self, event) -> None:
        doc = self.document()
        if not isinstance(doc, QCodeDocument):
            self._dismiss_nodetip()
            return

        pos = self.cursorForPosition(event.pos()).position()
        node = doc.get_node_at_position(pos)

        if node is None:
            self._dismiss_nodetip()
            return

        if self._node_tip.current_node is node:
            return

        self._node_tip.show_tip(node, self.mapToGlobal(event.pos()))

    def _dismiss_nodetip(self) -> None:
        self._node_tip.hide_tip()

    def leaveEvent(self, event) -> None:
        self._dismiss_nodetip()
        super().leaveEvent(event)

    def focusOutEvent(self, event) -> None:
        self._dismiss_nodetip()
        super().focusOutEvent(event)

    def wheelEvent(self, event) -> None:
        self._dismiss_nodetip()
        super().wheelEvent(event)

    def mousePressEvent(self, event) -> None:
        self._dismiss_nodetip()
        super().mousePressEvent(event)

    #
    # Actions
    #
    # pylint: disable=unused-argument
    def rename_node(self, *args, node=None) -> None:  # pylint: disable=unused-argument
        n = node if node is not None else self._selected_node
        if not isinstance(n, VariableNode | FunctionNode | FunctionCallNode | StructFieldNode | SimType):
            return
        if isinstance(n, VariableNode) and isinstance(n.variable, SimTemporaryVariable):
            # unsupported right now..
            return
        dialog = RenameNode(code_view=self._code_view, node=n, func=self._code_view.function)
        dialog.exec_()

    def xref_node(self, *args, node=None) -> None:  # pylint: disable=unused-argument
        n = node if node is not None else self._selected_node
        target = self.presenter.xref_target(n)
        if target is None:
            return
        dialog = XRefDialog(
            **target,
            instance=self.instance,
            disassembly_view=self._code_view,
            parent=self._code_view,
        )
        dialog.exec_()

    def _set_user_prototype(self, proto: SimTypeFunction) -> dict:
        # mark the prototype as user-provided. the decompiler will re-derive any prototype that it inferred itself.
        # returns the renames and manual types that the re-decompilation will drop
        return self.presenter.set_user_prototype(proto)

    def retype_node(self, *args, node=None, node_type=None) -> None:  # pylint: disable=unused-argument
        if node is None:
            node = self._selected_node
        if not isinstance(node, VariableNode | FunctionNode | FunctionCallNode | StructFieldNode):
            return
        if isinstance(node, VariableNode) and isinstance(node.variable, SimTemporaryVariable):
            # unsupported right now..
            return
        if node_type is None and hasattr(node, "type"):
            node_type = node.type
        dialog = RetypeNode(self.instance, code_view=self._code_view, node=node, node_type=node_type)
        dialog.exec_()

        new_node_type = dialog.new_type
        if new_node_type is not None and self._code_view is not None and node is not None:
            self.presenter.apply_retype(node, new_node_type)

    def comment(self, expr: bool = False, node=None, inline: bool = True) -> None:
        addr = self.get_closest_insaddr(node, expr=expr)
        if addr is None:
            return

        if expr:
            self._comment_expr(addr)
            return

        # statement comments go into kb.comments so they survive re-decompilation and show up in
        # the disassembly too; the edit layer mirrors them into codegen.stmt_comments
        kb = self._code_view.instance.kb
        text = "" if kb is None else kb.comments.get(addr, "")
        if inline and "\n" not in text:
            self.begin_inline_comment(addr, text)
            return

        text, ok = QInputDialog.getText(
            self._code_view, "Statement Comment", "", QLineEdit.EchoMode.Normal, text.replace("\n", " ")
        )
        if ok:
            self._commit_inline_comment(addr, text)

    def begin_inline_comment(self, addr: int, text: str) -> QInlineCommentEditor:
        """
        Edit the comment for ``addr`` in a one-line editor floating at the text cursor.
        """
        if self._inline_comment_editor is not None:
            self._inline_comment_editor.cancel()
        editor = QInlineCommentEditor(self, addr, text, self._commit_inline_comment)
        rect = self.cursorRect()
        editor.show_at(rect.bottomLeft(), self.viewport().width() // 2)
        self._inline_comment_editor = editor
        return editor

    def _commit_inline_comment(self, addr: int, text: str) -> None:
        self._inline_comment_editor = None
        self.workspace.set_comment(addr, text)

    def _comment_expr(self, addr: int) -> None:
        try:
            cdict = self._code_view.codegen.expr_comments
        except AttributeError:
            return
        text = cdict.get(addr, "")

        text, ok = QInputDialog.getText(self._code_view, "Expression Comment", "", QLineEdit.EchoMode.Normal, text)

        if ok:
            self.presenter.set_expr_comment(addr, text)

    def toggle_struct(self) -> None:
        self.presenter.toggle_struct(self._selected_node)

    def collapse_expr(self) -> None:
        self.presenter.collapse_expr(self._selected_node)

    def expand_expr(self) -> None:
        self.presenter.expand_expr(self._selected_node)

    def hex_constant(self) -> None:
        self.presenter.hex_constant(self._selected_node)

    def char_constant(self) -> None:
        self.presenter.char_constant(self._selected_node)

    def neg_constant(self) -> None:
        self.presenter.neg_constant(self._selected_node)

    def float_constant(self) -> None:
        self.presenter.float_constant(self._selected_node)

    def double_constant(self) -> None:
        self.presenter.double_constant(self._selected_node)

    def create_pattern(self, call_name: str | None = None) -> PatternView | None:
        """Turn the selected text into a pattern and open it in the editor view.

        ``call_name`` is asked for when not given. Returns the view, or None when there
        is no selection, no decompilation, or nothing whole inside the selection.
        """
        cursor = self.textCursor()
        start, end = cursor.selectionStart(), cursor.selectionEnd()
        if start >= end:
            _l.warning("Select the statements the pattern should cover first.")
            return None
        graph = self.presenter.pattern_graph()
        if graph is None:
            return None
        if call_name is None:
            call_name, ok = QInputDialog.getText(self, "Pattern", "Name of the call the pattern becomes:")
            if not ok or not call_name.strip():
                return None
        pattern = self.presenter.make_pattern(start, end, call_name, graph)
        if pattern is None:
            return None
        function = self._code_view.function
        view = self.workspace._get_or_create_view("pattern", PatternView, position="center")
        view.load_pattern(pattern, origin_func=function.addr)
        self.workspace.raise_view(view)
        return view

    def convert_to_ite_expr(self) -> None:
        self.presenter.convert_to_ite_expr(self._selected_node)

    def swap_binop_operands(self) -> None:
        self.presenter.swap_binop_operands(self._selected_node)

    def expr2armasm(self) -> None:
        self.presenter.expr2armasm(self._selected_node)

    #
    # Private methods
    #

    @staticmethod
    def _separator():
        sep = QAction()
        sep.setSeparator(True)
        return sep

    def _llm_refine_all(self) -> None:
        self.presenter.llm_refine_all()

    def _llm_suggest_var_names(self) -> None:
        self.presenter.llm_suggest_var_names()

    def _llm_suggest_func_name(self) -> None:
        self.presenter.llm_suggest_func_name()

    def _llm_suggest_var_types(self) -> None:
        self.presenter.llm_suggest_var_types()

    def _initialize_context_menus(self) -> None:
        base_actions = [
            self._separator(),
            self.action_copy,
            self.action_select_all,
        ]

        self.action_rename_node = QAction("Rename...", self)
        self.action_rename_node.triggered.connect(self.rename_node)
        self.action_rename_node.setShortcut(QKeySequence("N"))
        self.action_xref = QAction("Xrefs...", self)
        self.action_xref.triggered.connect(self.xref_node)
        self.action_xref.setShortcut(QKeySequence("X"))
        self.action_retype_node = QAction("Specify a new type", self)
        self.action_retype_node.triggered.connect(self.retype_node)
        self.action_retype_node.setShortcut(QKeySequence("Y"))
        self.action_toggle_struct = QAction("Toggle &struct/array")
        self.action_toggle_struct.triggered.connect(self.toggle_struct)
        self.action_collapse_expr = QAction("Collapse expression", self)
        self.action_collapse_expr.triggered.connect(self.collapse_expr)
        self.action_expand_expr = QAction("Expand expression", self)
        self.action_expand_expr.triggered.connect(self.expand_expr)
        self.action_hex = QAction("Toggle hex", self)
        self.action_hex.triggered.connect(self.hex_constant)
        self.action_hex.setShortcut(QKeySequence("H"))
        self.action_neg = QAction("Toggle negative", self)
        self.action_neg.triggered.connect(self.neg_constant)
        self.action_neg.setShortcut(QKeySequence("_"))
        self.action_char = QAction("Toggle char", self)
        self.action_char.triggered.connect(self.char_constant)
        self.action_char.setShortcut(QKeySequence("R"))
        self.action_float = QAction("Toggle float", self)
        self.action_float.triggered.connect(self.float_constant)
        self.action_double = QAction("Toggle double", self)
        self.action_double.triggered.connect(self.double_constant)
        self.action_to_ite_expr = QAction("Create a ternary expression")
        self.action_to_ite_expr.triggered.connect(self.convert_to_ite_expr)
        self.action_swap_binop_operands = QAction("Swap operands")
        self.action_swap_binop_operands.triggered.connect(self.swap_binop_operands)
        self.action_comment = QAction("Comment...", self)
        # triggered passes the checked state, which comment and create_pattern would take for an argument
        self.action_comment.triggered.connect(lambda: self.comment())  # pylint:disable=unnecessary-lambda
        self.action_comment.setShortcut(QKeySequence(";"))
        self.action_pattern = QAction("Create pattern from selection...", self)
        self.action_pattern.triggered.connect(lambda: self.create_pattern())  # pylint:disable=unnecessary-lambda
        self.action_clear_pattern_highlights = QAction("Clear pattern highlights", self)
        self.action_clear_pattern_highlights.triggered.connect(
            lambda: self._code_view.clear_pattern_highlight()  # pylint:disable=unnecessary-lambda
        )

        expr_actions = [
            self.action_to_ite_expr,
            self.action_swap_binop_operands,
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
            self.action_xref,
        ]

        self.function_name_actions = [self.action_rename_node, self.action_xref, self.action_retype_node]

        self.constant_actions = [
            self.action_hex,
            self.action_neg,
            self.action_char,
            self.action_float,
            self.action_double,
        ]

        self.call_actions = [self.action_rename_node, self.action_xref]

        comment_actions = [self.action_comment, self.action_pattern]

        self.constant_actions += comment_actions + base_actions + expr_actions
        self.operator_actions += comment_actions + base_actions + expr_actions
        self.variable_actions += comment_actions + base_actions + expr_actions
        self.function_name_actions += comment_actions + base_actions
        self.call_actions += comment_actions + base_actions + expr_actions
        self.default_actions += comment_actions + base_actions

        # LLM actions
        self.action_llm_refine_all = QAction("AI: Refine All", self)
        self.action_llm_refine_all.triggered.connect(self._llm_refine_all)
        self.action_llm_suggest_var_names = QAction("AI: Suggest Variable Names", self)
        self.action_llm_suggest_var_names.triggered.connect(self._llm_suggest_var_names)
        self.action_llm_suggest_func_name = QAction("AI: Suggest Function Name", self)
        self.action_llm_suggest_func_name.triggered.connect(self._llm_suggest_func_name)
        self.action_llm_suggest_var_types = QAction("AI: Suggest Variable Types", self)
        self.action_llm_suggest_var_types.triggered.connect(self._llm_suggest_var_types)
        self.llm_actions = [
            self._separator(),
            self.action_llm_refine_all,
            self.action_llm_suggest_var_names,
            self.action_llm_suggest_func_name,
            self.action_llm_suggest_var_types,
        ]
