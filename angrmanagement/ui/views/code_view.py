from typing import Set

from PySide2.QtWidgets import QHBoxLayout, QTextEdit, QMainWindow, QDockWidget
from PySide2.QtGui import QTextCursor
from PySide2.QtCore import Qt

from angr.analyses.decompiler.structured_codegen import CFunctionCall, CConstant, StructuredCodeGenerator

from ..widgets.qccode_edit import QCCodeEdit
from ..widgets.qdecomp_options import QDecompilationOptions
from ..documents import QCodeDocument
from .view import BaseView
from ...data.object_container import ObjectContainer
from ...logic.disassembly import JumpHistory
from ...data.jobs import DecompileFunctionJob


class CodeView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('pseudocode', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Pseudocode'

        self.function = ObjectContainer(None, 'The function to decompile')
        self.current_node = ObjectContainer(None, 'Current selected C-code node')

        self._codeedit = None
        self._codegen = ObjectContainer(None, "The currently-displayed codegen object")
        self._textedit: QCCodeEdit = None
        self._doc = None  # type:QCodeDocument
        self._options = None  # type:QDecompilationOptions
        self.jump_history = JumpHistory()

        self.vars_must_struct: Set[str] = set()

        self._init_widgets()

        self._textedit.cursorPositionChanged.connect(self._on_cursor_position_changed)
        self._textedit.selectionChanged.connect(self._on_cursor_position_changed)
        self._textedit.mouse_double_clicked.connect(self._on_mouse_doubleclicked)
        self.function.am_subscribe(self._on_new_function)
        self._codegen.am_subscribe(self._on_new_codegen)

    def reload(self):
        if self.workspace.instance.project.am_none:
            return
        self._options.reload(force=True)
        self.vars_must_struct = set()

    def decompile(self, clear_prototype: bool=True, focus=False, focus_addr=None):
        if self.function.am_none:
            return

        if clear_prototype:
            # clear the existing function prototype
            self.function.prototype = None

        def decomp_ready():
            self._codegen.am_obj = job.result.codegen
            self._codegen.am_event()
            self.focus(focus_addr, focus)

        job = DecompileFunctionJob(
            self.function.am_obj,
            flavor='pseudocode',
            cfg=self.workspace.instance.cfg,
            options=self._options.option_and_values,
            optimization_passes=self._options.selected_passes,
            peephole_optimizations=self._options.selected_peephole_opts,
            vars_must_struct=self.vars_must_struct,
            on_finish=decomp_ready,
        )

        self.workspace.instance.add_job(job)

    def focus(self, focus_addr=None, focus=True):
        if focus:
            self.workspace.view_manager.raise_view(self)
        if focus_addr is not None:
            # get closest node for ins
            new_text_pos = self._doc.find_closest_node_pos(focus_addr)

            if new_text_pos is not None:
                # set the new cursor position
                textedit = self.textedit
                cursor = textedit.textCursor()
                cursor.setPosition(new_text_pos)
                textedit.setTextCursor(cursor)
                textedit.setFocus()

    def _on_new_codegen(self):
        self._doc = QCodeDocument(self.codegen)
        self._textedit.setDocument(self._doc)

    #
    # Properties
    #

    @property
    def textedit(self):
        return self._textedit

    @property
    def document(self):
        return self._doc

    @property
    def codegen(self) -> StructuredCodeGenerator:
        return self._codegen.am_obj

    #
    # Public methods
    #

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

    def refresh_text(self, func_name=None):
        if self.codegen is not None:
            # add new name if available
            if func_name is not None:
                self.codegen.regenerate_text(func_name=func_name)
            else:
                self.codegen.regenerate_text()

            self.set_codegen(self.codegen)

    #
    # Event callbacks
    #

    def _on_new_function(self, focus=False, focus_addr=None, **kwargs):
        if self.codegen is not None and self.codegen._func is self.function.am_obj:
            self.focus(focus_addr, focus=focus)
            return
        self.decompile(focus=focus, focus_addr=focus_addr)

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
                    self.workspace.jump_to(selected_node.value.value)

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_Tab:
            # Compute the location to switch back to
            asm_inst_addr = self._textedit.get_src_to_inst()

            # Switch back to disassembly view
            self.workspace.jump_to(asm_inst_addr)
            return True
        elif key == Qt.Key_Escape:
            addr = self.jump_history.backtrack()
            if addr is None:
                self.workspace.view_manager.remove_view(self)
            else:
                target_func = self.workspace.instance.kb.functions.floor_func(addr)
                self.workspace.decompile_function(target_func, curr_ins=addr, view=self)
            return True

        return super().keyPressEvent(event)

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

        layout = QHBoxLayout()
        layout.addWidget(window)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        self._textedit.focusWidget()

        self.workspace.plugins.instrument_code_view(self)
