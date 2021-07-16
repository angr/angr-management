from typing import Set, Union, Optional
import logging

from PySide2.QtWidgets import QHBoxLayout, QTextEdit, QMainWindow, QDockWidget, QVBoxLayout, QWidget, QFrame, QComboBox
from PySide2.QtGui import QTextCursor
from PySide2.QtCore import Qt

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CConstant, CStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.knowledge_plugins.functions.function import Function

from ..widgets.qccode_edit import QCCodeEdit
from ..widgets.qdecomp_options import QDecompilationOptions
from ..documents import QCodeDocument
from .view import BaseView
from ...data.object_container import ObjectContainer
from ...logic.disassembly import JumpHistory
from ...data.jobs import DecompileFunctionJob
from ..toolbars import NavToolbar


l = logging.getLogger(__name__)


class CodeView(BaseView):
    """
    A view to display pseudocode or source code. You should control this view by manipulating and observing its four
    ObjectContainers: .addr, .current_node, .codegen, and .function.
    """
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('pseudocode', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Pseudocode'

        self.function: Union[ObjectContainer, Function] = ObjectContainer(None, 'The function to decompile')
        self.current_node = ObjectContainer(None, 'Current selected C-code node')
        self.addr: Union[ObjectContainer, int] = ObjectContainer(0, "Current cursor address")
        self.codegen: Union[ObjectContainer, CStructuredCodeGenerator] = ObjectContainer(None, "The currently-displayed codegen object")

        self._last_function: Optional[Function] = None
        self._textedit: Optional[QCCodeEdit] = None
        self._doc: Optional[QCodeDocument] = None
        self._options: Optional[QDecompilationOptions] = None
        self.jump_history: JumpHistory = JumpHistory()
        self._nav_toolbar: Optional[NavToolbar] = None
        self._view_selector: Optional[QComboBox] = None

        self.vars_must_struct: Set[str] = set()

        self._init_widgets()

        self._textedit.cursorPositionChanged.connect(self._on_cursor_position_changed)
        self._textedit.selectionChanged.connect(self._on_cursor_position_changed)
        self._textedit.mouse_double_clicked.connect(self._on_mouse_doubleclicked)
        self.function.am_subscribe(self._on_new_function)
        self.codegen.am_subscribe(self._on_new_codegen)
        self.addr.am_subscribe(self._on_new_addr)
        self.current_node.am_subscribe(self._on_new_node)

    def _focus_core(self, focus, focus_addr):
        if focus:
            self.focus()
        if focus_addr is not None:
            self.addr.am_obj = focus_addr
            self.addr.am_event()

    #
    # Properties
    #

    @property
    def textedit(self):
        return self._textedit

    @property
    def document(self):
        return self._doc

    #
    # Public methods
    #

    def reload(self):
        if self.workspace.instance.project.am_none:
            return
        self._options.reload(force=True)
        self.vars_must_struct = set()

    def decompile(self, clear_prototype: bool=True, focus=False, focus_addr=None, flavor='pseudocode'):
        if self.function.am_none:
            return

        if clear_prototype:
            # clear the existing function prototype
            self.function.prototype = None

        def decomp_ready():
            # this code is _partially_ duplicated from _on_new_function. be careful!
            available = self.workspace.instance.kb.structured_code.available_flavors(self.function.addr)
            self._update_available_views(available)
            if available:
                chosen_flavor = flavor if flavor in available else available[0]
                self.codegen.am_obj = self.workspace.instance.kb.structured_code[(self.function.addr, chosen_flavor)]
                self.codegen.am_event(already_regenerated=True)
                self._focus_core(focus, focus_addr)
                if focus_addr is not None:
                    self.jump_history.record_address(focus_addr)
                else:
                    self.jump_history.record_address(self.function.am_obj.addr)

        job = DecompileFunctionJob(
            self.function.am_obj,
            cfg=self.workspace.instance.cfg,
            options=self._options.option_and_values,
            optimization_passes=self._options.selected_passes,
            peephole_optimizations=self._options.selected_peephole_opts,
            vars_must_struct=self.vars_must_struct,
            on_finish=decomp_ready,
        )

        self.workspace.instance.add_job(job)

    def highlight_chunks(self, chunks):
        extra_selections = [ ]
        for start, end in chunks:
            sel = QTextEdit.ExtraSelection()
            sel.cursor = self._textedit.textCursor()
            sel.cursor.setPosition(start)
            sel.cursor.setPosition(end, QTextCursor.KeepAnchor)
            sel.format.setBackground(Qt.yellow)
            extra_selections.append(sel)
        self._textedit.setExtraSelections(extra_selections)

    #
    # Event callbacks
    #

    def _on_new_addr(self, already_moved=False, focus=False, **kwargs):  # pylint: disable=unused-argument
        if already_moved:
            return

        # get closest node for ins
        new_text_pos = self._doc.find_closest_node_pos(self.addr.am_obj) if self._doc is not None else None

        if new_text_pos is not None:
            # set the new cursor position
            textedit = self.textedit
            cursor = textedit.textCursor()
            cursor.setPosition(new_text_pos)
            textedit.setTextCursor(cursor)
            if focus:
                textedit.setFocus()
                self._focus_core(True, None)
        else:
            # try to find the right function
            block_addr, _ = self.workspace.instance.cfb.floor_item(self.addr.am_obj)
            block = self.workspace.instance.cfg.get_any_node(block_addr)
            if block is not None:
                func = self.workspace.instance.kb.functions[block.function_address]
                if func is not self.function.am_obj:
                    self.function.am_obj = func
                    self.function.am_event(focus_addr=self.addr.am_obj, focus=focus)
                else:
                    l.error("There is a block which is in the current function but find_closest_node_pos failed on it")

    def _on_new_node(self, **kwargs):  # pylint: disable=unused-argument
        self.addr.am_obj = self._textedit.get_src_to_inst()
        self.addr.am_event(already_moved=True)

    def _on_new_codegen(self, already_regenerated=False, **kwargs):  # pylint: disable=unused-argument
        self._view_selector.setCurrentText(self.codegen.flavor)
        if not already_regenerated:
            self.codegen.regenerate_text()

        old_pos: Optional[int] = None
        old_font = None
        if self._last_function is self.function.am_obj:
            # we are re-rendering the current function (e.g., triggered by a node renaming). save the old cursor and
            # reuse it later.
            old_cursor: QTextCursor = self._textedit.textCursor()
            old_pos = old_cursor.position()
            old_font = self._textedit.font()

        self._options.dirty = False
        self._doc = QCodeDocument(self.codegen)
        self._textedit.setDocument(self._doc)

        if old_pos is not None:
            new_cursor: QTextCursor = self._textedit.textCursor()
            new_cursor.setPosition(old_pos)
            self._textedit.setFont(old_font)
            self._textedit.setTextCursor(new_cursor)

        if self.codegen.flavor == 'pseudocode':
            self._options.show()
        else:
            self._options.hide()

    def _on_new_function(self, focus=False, focus_addr=None, flavor=None, **kwargs):  # pylint: disable=unused-argument
        # sets a new function. extra args are used in case this operation requires waiting for the decompiler
        if flavor is None:
            if self.codegen.am_none:
                flavor = 'pseudocode'
            else:
                flavor = self.codegen.flavor

        if not self.codegen.am_none and self._last_function is self.function.am_obj:
            self._focus_core(focus, focus_addr)
            return
        available = self.workspace.instance.kb.structured_code.available_flavors(self.function.addr)
        self._update_available_views(available)
        should_decompile = True
        if available:
            chosen_flavor = flavor if flavor in available else available[0]
            cached = self.workspace.instance.kb.structured_code[(self.function.addr, chosen_flavor)]
            if not isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = False
                self.codegen.am_obj = cached
                self.codegen.am_event()
                self._focus_core(focus, focus_addr)

        if should_decompile:
            self.decompile(focus=focus, focus_addr=focus_addr, flavor=flavor)
        self._last_function = self.function.am_obj

    def _on_cursor_position_changed(self):
        if self._doc is None:
            return

        cursor = self._textedit.textCursor()
        pos = cursor.position()
        selected_node = self._doc.get_node_at_position(pos)
        if selected_node is not None:
            # find all related text chunks and highlight them all
            chunks = self._doc.find_related_text_chunks(selected_node)
            # highlight these chunks
            self.highlight_chunks(chunks)
        else:
            self.highlight_chunks([ ])

        self.current_node.am_obj = selected_node
        self.current_node.am_event()

    def _on_mouse_doubleclicked(self):
        if self._doc is None:
            return

        cursor = self._textedit.textCursor()
        pos = cursor.position()
        selected_node = self._doc.get_node_at_position(pos)
        if selected_node is not None:
            if isinstance(selected_node, CFunctionCall):
                # decompile this new function
                if selected_node.callee_func is not None:
                    self.jump_history.record_address(selected_node.tags['ins_addr'])
                    self.jump_history.jump_to(selected_node.callee_func.addr)
                    self.workspace.decompile_function(selected_node.callee_func, view=self)
            elif isinstance(selected_node, CConstant):
                # jump to highlighted constants
                if selected_node.reference_values is not None and selected_node.value is not None:
                    self.workspace.jump_to(selected_node.value)

    def _jump_to(self, addr:int):
        self.addr.am_obj = addr
        self.addr.am_event()

    def jump_back(self):
        addr = self.jump_history.backtrack()
        if addr is None:
            self.close()
        else:
            self._jump_to(addr)

    def jump_forward(self):
        addr = self.jump_history.forwardstep()
        if addr is not None:
            self._jump_to(addr)

    def jump_to_history_position(self, pos:int):
        addr = self.jump_history.step_position(pos)
        if addr is not None:
            self._jump_to(addr)

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_Tab:
            # Switch back to disassembly view
            self.workspace.jump_to(self.addr.am_obj)
            return True
        elif key == Qt.Key_Escape:
            self.jump_back()
            return True
        elif key == Qt.Key_Space:
            if not self.codegen.am_none:
                flavor = self.codegen.flavor
                flavors = self.workspace.instance.kb.structured_code.available_flavors(self.function.addr)
                idx = flavors.index(flavor)
                newidx = (idx + 1) % len(flavors)
                self.codegen.am_obj = self.workspace.instance.kb.structured_code[(self.function.addr, flavors[newidx])]
                self.codegen.am_event()
                return True

        return super().keyPressEvent(event)

    def _update_available_views(self, available):
        for _ in range(self._view_selector.count()):
            self._view_selector.removeItem(0)
        self._view_selector.addItems(available)

    def _on_view_selector_changed(self, index):
        key = (self.function.addr, self._view_selector.itemText(index))
        self.codegen.am_obj = self.workspace.instance.kb.structured_code[key]
        self.codegen.am_event()

    #
    # Private methods
    #

    def _init_widgets(self):

        window = QMainWindow()
        window.setWindowFlags(Qt.Widget)

        # pseudo code text box
        self._textedit = QCCodeEdit(self)
        self._textedit.setTextInteractionFlags(Qt.TextSelectableByKeyboard | Qt.TextSelectableByMouse)
        self._textedit.setLineWrapMode(QCCodeEdit.NoWrap)
        textedit_dock = QDockWidget('Code', self._textedit)
        window.setCentralWidget(textedit_dock)
        textedit_dock.setWidget(self._textedit)

        # decompilation
        self._options = QDecompilationOptions(self, self.workspace.instance, options=None)
        options_dock = QDockWidget('Decompilation Options', self._options)
        window.addDockWidget(Qt.RightDockWidgetArea, options_dock)
        options_dock.setWidget(self._options)

        # status bar
        status_bar = QFrame()
        self._nav_toolbar = NavToolbar(
            self.jump_history,
            self.jump_back,
            self.jump_forward,
            self.jump_to_history_position,
            True, self)
        self._view_selector = QComboBox()
        self._view_selector.addItems(["pseudocode"])
        self._view_selector.activated.connect(self._on_view_selector_changed)
        status_layout = QHBoxLayout()
        status_layout.addWidget(self._nav_toolbar.qtoolbar())
        status_layout.addStretch(0)
        status_layout.addWidget(self._view_selector)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_bar.setLayout(status_layout)

        inner_layout = QHBoxLayout()
        inner_layout.addWidget(window)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_widget = QWidget()
        inner_widget.setLayout(inner_layout)

        outer_layout = QVBoxLayout()
        outer_layout.addWidget(inner_widget)
        outer_layout.addWidget(status_bar)

        self.setLayout(outer_layout)

        self._textedit.focusWidget()

        self.workspace.plugins.instrument_code_view(self)
