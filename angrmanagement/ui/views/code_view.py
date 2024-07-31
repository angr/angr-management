from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.structured_codegen import DummyStructuredCodeGenerator
from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall, CStructuredCodeGenerator, CVariable
from angr.knowledge_plugins.functions.function import Function
from angr.sim_variable import SimMemoryVariable
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf
from angrmanagement.data.jobs import DecompileFunctionJob, VariableRecoveryJob
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.logic.disassembly import JumpHistory
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.documents import QCodeDocument
from angrmanagement.ui.toolbars import NavToolbar
from angrmanagement.ui.widgets.qccode_edit import QCCodeEdit
from angrmanagement.ui.widgets.qdecomp_options import QDecompilationOptions

from .disassembly_view import DisassemblyView
from .view import FunctionView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(__name__)


class CodeView(FunctionView):
    """
    A view to display pseudocode or source code. You should control this view by manipulating and observing its four
    ObjectContainers: .addr, .current_node, .codegen, and .function.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("pseudocode", workspace, default_docking_position, instance)

        self.base_caption = "Pseudocode"

        self._function: ObjectContainer | Function = ObjectContainer(None, "The function to decompile")
        self.current_node = ObjectContainer(None, "Current selected C-code node")
        self.addr: ObjectContainer | int = ObjectContainer(0, "Current cursor address")
        self.codegen: ObjectContainer | CStructuredCodeGenerator = ObjectContainer(
            None, "The currently-displayed codegen object"
        )

        self._last_function: Function | None = None
        self._textedit: QCCodeEdit | None = None
        self._doc: QCodeDocument | None = None
        self._options: QDecompilationOptions | None = None
        self.jump_history: JumpHistory = JumpHistory()
        self._nav_toolbar: NavToolbar | None = None
        self._view_selector: QComboBox | None = None

        self.vars_must_struct: set[str] = set()

        self._init_widgets()

        self._textedit.cursorPositionChanged.connect(self._on_cursor_position_changed)
        self._textedit.selectionChanged.connect(self._on_cursor_position_changed)
        self._textedit.mouse_double_clicked.connect(self._on_mouse_doubleclicked)
        self._function.am_subscribe(self._on_new_function)
        self.codegen.am_subscribe(self._on_codegen_changes)
        self.addr.am_subscribe(self._on_new_addr)
        self.current_node.am_subscribe(self._on_new_node)

    def _focus_core(self, focus: bool, focus_addr: int) -> None:
        if focus:
            self.focus()
        if focus_addr is not None:
            self.addr.am_obj = focus_addr
            self.addr.am_event(focus=True)

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

    def reload(self) -> None:
        if self.instance.project.am_none:
            return
        self._options.reload(force=True)
        self.vars_must_struct = set()

    def decompile(
        self,
        clear_prototype: bool = True,
        focus: bool = False,
        focus_addr=None,
        flavor: str = "pseudocode",
        reset_cache: bool = False,
        regen_clinic: bool = True,
    ) -> None:
        if self._function.am_none:
            return

        if clear_prototype:
            # clear the existing function prototype
            self._function.prototype = None
            self._function.ran_cca = False

        if reset_cache:
            self.instance.kb.structured_code.discard((self._function.addr, flavor))
            variables = self.instance.pseudocode_variable_kb.variables
            if variables.has_function_manager(self._function.addr):
                del variables[self._function.addr]

        def decomp_ready(*args, **kwargs) -> None:  # pylint:disable=unused-argument
            # this code is _partially_ duplicated from _on_new_function. be careful!
            available = self.instance.kb.structured_code.available_flavors(self._function.addr)
            self._update_available_views(available)
            if available:
                chosen_flavor = flavor if flavor in available else available[0]
                self.codegen.am_obj = self.instance.kb.structured_code[(self._function.addr, chosen_flavor)].codegen
                self.codegen.am_event(already_regenerated=True)
                self._focus_core(focus, focus_addr)
                if focus_addr is not None:
                    self.jump_history.record_address(focus_addr)
                else:
                    self.jump_history.record_address(self._function.am_obj.addr)

        def decomp(*_) -> None:
            job = DecompileFunctionJob(
                self.instance,
                self._function.am_obj,
                cfg=self.instance.cfg,
                options=self._options.option_and_values,
                optimization_passes=self._options.selected_passes,
                peephole_optimizations=self._options.selected_peephole_opts,
                vars_must_struct=self.vars_must_struct,
                on_finish=decomp_ready,
                blocking=True,
                regen_clinic=regen_clinic,
            )
            self.workspace.job_manager.add_job(job)

        if self._function.ran_cca is False:
            # run calling convention analysis for this function
            if self.instance._analysis_configuration:
                options = self.instance._analysis_configuration["varec"].to_dict()
            else:
                options = {}
            options["workers"] = 0
            varrec_job = VariableRecoveryJob(self.instance, **options, on_finish=decomp, func_addr=self._function.addr)
            self.workspace.job_manager.add_job(varrec_job)
        else:
            decomp()

    def highlight_chunks(self, chunks) -> None:
        extra_selections = []
        for start, end in chunks:
            sel = QTextEdit.ExtraSelection()
            sel.cursor = self._textedit.textCursor()
            sel.cursor.setPosition(start)
            sel.cursor.setPosition(end, QTextCursor.MoveMode.KeepAnchor)
            sel.format.setBackground(Conf.pseudocode_highlight_color)
            extra_selections.append(sel)
        self._textedit.setExtraSelections(extra_selections)

    #
    # Event callbacks
    #

    def _on_new_addr(
        self, already_moved: bool = False, focus: bool = False, **kwargs  # pylint:disable=unused-argument
    ) -> None:
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
            block_addr, _ = self.instance.cfb.floor_item(self.addr.am_obj)
            block = self.instance.cfg.get_any_node(block_addr)
            if block is not None:
                func = self.instance.kb.functions[block.function_address]
                if func is not self._function.am_obj:
                    self._function.am_obj = func
                    self._function.am_event(focus_addr=self.addr.am_obj, focus=focus)
                else:
                    log.error(
                        "There is a block which is in the current function but find_closest_node_pos failed on it"
                    )

    def _on_new_node(self, **kwargs) -> None:  # pylint: disable=unused-argument
        self.addr.am_obj = self._textedit.get_src_to_inst()
        self.addr.am_event(already_moved=True)

    # pylint: disable=unused-argument
    def _on_codegen_changes(self, already_regenerated: bool = False, event: str | None = None, **kwargs) -> None:
        """
        The callback function that triggers an update of the codegen.

        :param already_regenerated: True if we only want to re-render the text and do not intend to change the text.
                                    Setting it to True will ignore `event` and other parameters.
        :param event:               The event to perform. For example, "retype_variable" will cause a re-flow of
                                    variable types. Leaving it unspecified will lead to regeneration of text (which is
                                    the default behavior).
                                    Supported events: retype_variable
        :param kwargs:              Keyword arguments that are required in each event.
        :return:
        """
        if self.codegen.am_none:
            return

        old_lineno: int | None = None
        old_node: Any | None = None
        old_font = None
        if self._last_function is self._function.am_obj and self._doc is not None:
            # we are re-rendering the current function (e.g., triggered by a node renaming). the cursor should stay at
            # the same node
            old_cursor: QTextCursor = self._textedit.textCursor()
            old_pos = old_cursor.position()
            old_lineno = old_cursor.blockNumber()
            old_font = self._textedit.font()
            # TODO: If multiple instances of the node is referenced at the same line, we will always select the first
            #  node. We need to fix this by counting which node is selected.
            old_node = self._doc.get_node_at_position(old_pos)

        self._view_selector.setCurrentText(self.codegen.flavor)

        if already_regenerated:
            # do not regenerate text
            pass
        else:
            update_var_types = False
            if event == "retype_variable":
                dec = self.instance.project.analyses.Decompiler(
                    self._function.am_obj, variable_kb=self.instance.pseudocode_variable_kb, decompile=False
                )
                dec_cache = self.instance.kb.structured_code[(self._function.addr, "pseudocode")]
                new_codegen = dec.reflow_variable_types(
                    dec_cache.type_constraints,
                    dec_cache.func_typevar,
                    dec_cache.var_to_typevar or {},
                    dec_cache.codegen,
                )
                # update the cache
                dec_cache.codegen = new_codegen

                # update self
                self.codegen.am_obj = new_codegen
                update_var_types = True
            elif event == "retype_function":
                self.decompile(clear_prototype=False, reset_cache=True)
                update_var_types = True

            if not update_var_types:
                # regenerate text in the end
                self.codegen.regenerate_text()
            else:
                # trigger a full analysis
                self.codegen.cleanup()
                self.codegen._analyze()

        self._options.dirty = False
        if self._doc is None:
            self._doc = QCodeDocument(self.codegen)
            self._textedit.setDocument(self._doc)
        else:
            # only update the text. do not set a new document. this avoids scrolling the textedit up and down
            self._doc._codegen = self.codegen
            self._doc.setPlainText(self.codegen.text)

        if old_lineno is not None:
            the_block = self._doc.findBlockByNumber(old_lineno)
            new_cursor: QTextCursor = QTextCursor(the_block)
            self._textedit.setFont(old_font)
            if old_node is not None:
                # find the first node starting from the current position
                for pos in self.codegen.map_pos_to_node._posmap.irange(
                    minimum=new_cursor.position(), maximum=new_cursor.position() + the_block.length()
                ):
                    elem = self.codegen.map_pos_to_node._posmap[pos]
                    if elem.obj is old_node:
                        new_cursor.setPosition(pos)
            self._textedit.setTextCursor(new_cursor)

        if self.codegen.flavor == "pseudocode":
            self._options.show()
        else:
            self._options.hide()

    def _on_new_function(
        self, focus: bool = False, focus_addr=None, flavor=None, **kwargs
    ) -> None:  # pylint: disable=unused-argument
        # sets a new function. extra args are used in case this operation requires waiting for the decompiler
        if flavor is None:
            flavor = "pseudocode" if self.codegen.am_none else self.codegen.flavor

        if not self.codegen.am_none and self._last_function is self._function.am_obj:
            self._focus_core(focus, focus_addr)
            return
        available = self.instance.kb.structured_code.available_flavors(self._function.addr)
        self._update_available_views(available)
        should_decompile = True
        if available:
            chosen_flavor = flavor if flavor in available else available[0]
            cached = self.instance.kb.structured_code[(self._function.addr, chosen_flavor)].codegen
            if not isinstance(cached, DummyStructuredCodeGenerator):
                should_decompile = False
                self.codegen.am_obj = cached
                self.codegen.am_event()
                self._focus_core(focus, focus_addr)

        if should_decompile:
            self.decompile(focus=focus, focus_addr=focus_addr, flavor=flavor)
        self._last_function = self._function.am_obj

        console_view = self.workspace.view_manager.first_view_in_category("console")
        if console_view is not None:
            console_view.set_current_function(self._function.am_obj)

    def _on_cursor_position_changed(self) -> None:
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
            self.highlight_chunks([])

        self.current_node.am_obj = selected_node
        self.current_node.am_event()

    def _navigate_to_function(self, from_addr: int, to_func: Function) -> None:
        self.jump_history.record_address(from_addr)
        self.jump_history.jump_to(to_func.addr)
        self.workspace.decompile_function(to_func, view=self)

    def _on_mouse_doubleclicked(self) -> None:
        if self._doc is None:
            return

        cursor = self._textedit.textCursor()
        pos = cursor.position()
        selected_node = self._doc.get_node_at_position(pos)
        if selected_node is not None:
            if isinstance(selected_node, CFunctionCall):
                # decompile this new function
                if selected_node.callee_func is not None:
                    self._navigate_to_function(selected_node.tags["ins_addr"], selected_node.callee_func)
            elif isinstance(selected_node, CConstant):
                # jump to highlighted constants
                if selected_node.reference_values is not None and selected_node.value is not None:
                    for v in selected_node.reference_values.values():
                        if isinstance(v, Function):
                            self._navigate_to_function(selected_node.tags["ins_addr"], v)
                            return
                    self.workspace.jump_to(selected_node.value)
            elif isinstance(selected_node, CVariable):
                var = selected_node.variable
                if var and isinstance(var, SimMemoryVariable):
                    self.workspace.jump_to(var.addr)

    def jump_to(self, addr: int, src_ins_addr=None) -> None:  # pylint:disable=unused-argument
        self.addr.am_obj = addr
        self.addr.am_event()

    def jump_back(self) -> None:
        addr = self.jump_history.backtrack()
        if addr is None:
            self.close()
        else:
            self.jump_to(addr)

    def popup_jumpto_dialog(self) -> None:
        view = self.workspace._get_or_create_view("disassembly", DisassemblyView)
        JumpTo(view, parent=self).exec_()
        view.decompile_current_function()

    def jump_forward(self) -> None:
        addr = self.jump_history.forwardstep()
        if addr is not None:
            self.jump_to(addr)

    def jump_to_history_position(self, pos: int) -> None:
        addr = self.jump_history.step_position(pos)
        if addr is not None:
            self.jump_to(addr)

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_Tab:
            # Switch back to disassembly view
            self.workspace.jump_to(self.addr.am_obj)
            return True
        elif key == Qt.Key_G:
            # jump to window
            self.popup_jumpto_dialog()
            return True
        elif key == Qt.Key_Escape:
            self.jump_back()
            return True
        elif key == Qt.Key_Space and not self.codegen.am_none:
            flavor = self.codegen.flavor
            flavors = self.instance.kb.structured_code.available_flavors(self._function.addr)
            idx = flavors.index(flavor)
            newidx = (idx + 1) % len(flavors)
            self.codegen.am_obj = self.instance.kb.structured_code[(self._function.addr, flavors[newidx])].codegen
            self.codegen.am_event()
            return True

        return super().keyPressEvent(event)

    def _update_available_views(self, available) -> None:
        for _ in range(self._view_selector.count()):
            self._view_selector.removeItem(0)
        self._view_selector.addItems(available)
        self._view_selector.setVisible(len(available) >= 2)

    def _on_view_selector_changed(self, index) -> None:
        if not self._function.am_none:
            key = (self._function.addr, self._view_selector.itemText(index))
            self.codegen.am_obj = self.instance.kb.structured_code[key].codegen
            self.codegen.am_event()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        window = QMainWindow()
        window.setWindowFlags(Qt.WindowType.Widget)

        # pseudo code text box
        self._textedit = QCCodeEdit(self)
        self._textedit.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._textedit.setLineWrapMode(QCCodeEdit.NoWrap)
        self._textedit.background = Conf.palette_base
        window.setCentralWidget(self._textedit)

        # decompilation options
        self._options = QDecompilationOptions(self, self.instance)
        options_dock = QDockWidget("Decompilation Options", self._options)
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, options_dock)
        options_dock.setWidget(self._options)
        options_dock.setVisible(False)

        # status bar
        status_bar = QFrame()
        self._nav_toolbar = NavToolbar(
            self.jump_history, self.jump_back, self.jump_forward, self.jump_to_history_position, True, self
        )
        self._view_selector = QComboBox()
        self._view_selector.addItems(["Pseudocode"])
        self._view_selector.activated.connect(self._on_view_selector_changed)
        status_layout = QHBoxLayout()
        status_layout.addWidget(self._nav_toolbar.qtoolbar())
        status_layout.addStretch(0)
        options_toggle_btn = QToolButton()
        options_toggle_btn.setDefaultAction(options_dock.toggleViewAction())
        status_layout.addWidget(options_toggle_btn)
        status_layout.addWidget(self._view_selector)
        status_layout.setContentsMargins(3, 3, 3, 3)
        status_layout.setSpacing(3)
        status_bar.setLayout(status_layout)

        inner_layout = QHBoxLayout()
        inner_layout.addWidget(window)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.setSpacing(0)
        inner_widget = QWidget()
        inner_widget.setLayout(inner_layout)

        outer_layout = QVBoxLayout()
        outer_layout.addWidget(status_bar)
        outer_layout.addWidget(inner_widget)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.setLayout(outer_layout)

        self._textedit.focusWidget()

        self.workspace.plugins.instrument_code_view(self)
