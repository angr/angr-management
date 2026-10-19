from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QCursor, QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QHBoxLayout, QMenu, QVBoxLayout

from angrmanagement.logic import GlobalInfo
from angrmanagement.present import disasm as present_disasm
from angrmanagement.present.dialogs import func_doc_target
from angrmanagement.present.disasm import DisasmPresenter, register_disasm_commands
from angrmanagement.ui.dialogs.assemble_patch import AssemblePatchDialog
from angrmanagement.ui.dialogs.dependson import DependsOn
from angrmanagement.ui.dialogs.func_doc import FuncDocDialog
from angrmanagement.ui.dialogs.hook import HookDialog
from angrmanagement.ui.dialogs.jumpto import JumpTo
from angrmanagement.ui.dialogs.new_state import NewState
from angrmanagement.ui.dialogs.rename import RenameDialog
from angrmanagement.ui.dialogs.rename_label import RenameLabel
from angrmanagement.ui.dialogs.set_comment import SetComment
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.menus import Menu
from angrmanagement.ui.menus.disasm_insn_context_menu import DisasmInsnContextMenu
from angrmanagement.ui.menus.disasm_label_context_menu import DisasmLabelContextMenu
from angrmanagement.ui.menus.disasm_unknown_context_menu import DisasmUnknownContextMenu
from angrmanagement.ui.views.symexec_view import SymexecView
from angrmanagement.ui.widgets import (
    DisassemblyLevel,
    QAvoidAddrAnnotation,
    QBlockAnnotations,
    QDisasmStatusBar,
    QDisassemblyGraph,
    QFindAddrAnnotation,
    QLinearDisassembly,
)
from angrmanagement.ui.widgets.block_code_objects import QVariableObj
from angrmanagement.ui.widgets.qfind_bar import QFindBar
from angrmanagement.ui.widgets.qinline_comment_editor import QInlineCommentEditor
from angrmanagement.ui.widgets.qinst_annotation import QBreakAnnotation, QHookAnnotation, QMarkAnnotation

from .view import SynchronizedFunctionView

if TYPE_CHECKING:
    import PySide6
    from angr.knowledge_plugins import VariableManager

    from angrmanagement.data.instance import Instance, ObjectContainer
    from angrmanagement.logic.disassembly import InfoDock, JumpHistory
    from angrmanagement.ui.workspace import Workspace


_l = logging.getLogger(__name__)

#: the presenter's, re-exported for code that imports it here; it throttles the listing's refreshes during CFG recovery
MIN_OBJECTS_ADDED_REFRESH_INTERVAL = present_disasm.MIN_OBJECTS_ADDED_REFRESH_INTERVAL


def _forward(name: str, doc: str | None = None):
    """A property that reads and writes the presenter's attribute ``name``."""

    def fget(self):
        return getattr(self.presenter, name)

    def fset(self, value) -> None:
        setattr(self.presenter, name, value)

    return property(fget, fset, doc=doc or f"The presenter's ``{name}``.")


class DisassemblyView(SynchronizedFunctionView):
    """
    Disassembly View

    The state and the actions are the :class:`~angrmanagement.present.disasm.DisasmPresenter`'s (``self.presenter``);
    this class adds the Qt controls, dialogs, menus and keys, and forwards the rest.
    """

    view_visibility_changed = Signal()
    disassembly_level_changed = Signal(DisassemblyLevel)

    FIND_HIGHLIGHT_LIMIT = DisasmPresenter.FIND_HIGHLIGHT_LIMIT
    FIND_MODE_TEXT = DisasmPresenter.FIND_MODE_TEXT
    FIND_MODE_TEXT_INSN = DisasmPresenter.FIND_MODE_TEXT_INSN
    FIND_MODE_BYTES = DisasmPresenter.FIND_MODE_BYTES

    presenter: DisasmPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        presenter = DisasmPresenter(workspace, instance, default_docking_position)
        super().__init__("disassembly", workspace, default_docking_position, instance, presenter=presenter)
        presenter.level_changed.connect(self.disassembly_level_changed.emit)
        presenter.view_visibility_changed.connect(self.view_visibility_changed.emit)

        self._statusbar = None
        self._insn_menu: DisasmInsnContextMenu | None = None
        self._label_menu: DisasmLabelContextMenu | None = None
        self._inline_comment_editor: QInlineCommentEditor | None = None

        self.width_hint = 800
        self.height_hint = 800

        self._find_bar: QFindBar | None = None

        self._init_widgets()
        self._init_menus()
        presenter.attach(self)
        self._init_shortcuts()

    @classmethod
    def register_commands(cls, workspace: Workspace) -> None:
        """
        Register commands that can be run for this view. They run on the focused view's presenter.
        """
        register_disasm_commands(workspace)

    #
    # The presenter's state
    #

    infodock: InfoDock = _forward("infodock")  # type: ignore[assignment]
    jump_history: JumpHistory = _forward("jump_history")  # type: ignore[assignment]
    variable_manager: VariableManager | None = _forward("variable_manager")  # type: ignore[assignment]
    pattern_highlight_addrs: set[int] = _forward(  # type: ignore[assignment]
        "pattern_highlight_addrs", "instructions a pattern or a discovered family covers, painted in their own color"
    )
    _insn_addr_on_context_menu = _forward("insn_addr_on_context_menu")
    _current_view = _forward("_current_view")
    _prefer_graph = _forward("_prefer_graph")
    _displaying_function = _forward("_displaying_function")
    _disassembly_level = _forward("_disassembly_level")
    _show_minimap = _forward("_show_minimap")
    _show_address = _forward("_show_address")
    _show_variable = _forward("_show_variable")
    _show_variable_ident = _forward("_show_variable_ident")
    _show_exception_edges = _forward("_show_exception_edges")
    _find_matches = _forward("_find_matches")
    _find_data_matches = _forward("_find_data_matches")
    _find_matches_capped = _forward("_find_matches_capped")
    _find_index = _forward("_find_index")
    _find_highlighted = _forward("_find_highlighted")
    _find_text_cache = _forward("_find_text_cache")
    _in_find_refresh = _forward("_in_find_refresh")
    _variable_recovery_flavor = _forward("_variable_recovery_flavor")

    @property
    def disassembly_level(self):
        return self.presenter.disassembly_level

    def set_disassembly_level(self, level: DisassemblyLevel) -> None:
        self.presenter.set_disassembly_level(level)

    def set_disassembly_level_ail(self) -> None:
        self.presenter.set_disassembly_level_ail()

    def set_disassembly_level_lifter_ir(self) -> None:
        self.presenter.set_disassembly_level_lifter_ir()

    def set_disassembly_level_machine_code(self) -> None:
        self.presenter.set_disassembly_level_machine_code()

    def reload(self) -> None:
        self.presenter.reload()

    def refresh(self) -> None:
        self.presenter.refresh()

    def save_image_to(self, path) -> None:
        if self._flow_graph is not None:
            self._flow_graph.save_image_to(path)

    def setFocus(self) -> None:
        self._flow_graph.setFocus()

    #
    # Properties
    #

    @property
    def disasm(self):
        return self._flow_graph.disasm

    @property
    def show_minimap(self):
        return self.presenter.show_minimap

    @property
    def smart_highlighting(self):
        return self.presenter.smart_highlighting

    @property
    def show_address(self):
        return self.presenter.show_address

    @property
    def show_variable(self):
        return self.presenter.show_variable

    @property
    def show_variable_identifier(self):
        return self.presenter.show_variable_identifier

    @property
    def show_exception_edges(self):
        return self.presenter.show_exception_edges

    @property
    def variable_recovery_flavor(self):
        return self.presenter.variable_recovery_flavor

    @variable_recovery_flavor.setter
    def variable_recovery_flavor(self, v) -> None:
        self.presenter.variable_recovery_flavor = v

    @property
    def current_graph(self) -> QLinearDisassembly | QDisassemblyGraph:
        """
        Return the current disassembly control, either linear viewer or flow graph.

        :return:    Linear viewer or flow graph.
        """
        return self.presenter.current_graph

    @property
    def current_function(self) -> ObjectContainer:
        return self.function

    @SynchronizedFunctionView.function.setter
    def function(self, v) -> None:
        self.display_function(v, send_event=False)

    #
    # Callbacks
    #

    # All callbacks are proxies to self.instance. These properties *in this class* may be removed in the near
    # future.
    @property
    def insn_backcolor_callback(self):
        return self.instance.insn_backcolor_callback

    @insn_backcolor_callback.setter
    def insn_backcolor_callback(self, v) -> None:
        self.instance.insn_backcolor_callback = v

    @property
    def label_rename_callback(self):
        return self.instance.label_rename_callback

    @label_rename_callback.setter
    def label_rename_callback(self, v) -> None:
        self.instance.label_rename_callback = v

    @property
    def set_comment_callback(self):
        return self.instance.set_comment_callback

    @set_comment_callback.setter
    def set_comment_callback(self, v) -> None:
        self.instance.set_comment_callback = v

    def on_cc_recovered(self, func_addr: int) -> None:
        self.presenter.on_cc_recovered(func_addr)

    def on_variable_recovered(self, func_addr: int) -> None:
        self.presenter.on_variable_recovered(func_addr)

    #
    # Events
    #

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key == Qt.Key.Key_G:
            # jump to window
            self.popup_jumpto_dialog()
            return
        elif key == Qt.Key.Key_Left and QApplication.keyboardModifiers() & Qt.Modifier.ALT != 0:
            # jump back
            self.jump_back()
            return
        elif key == Qt.Key.Key_Right and QApplication.keyboardModifiers() & Qt.Modifier.ALT != 0:
            # jump forward
            self.jump_forward()
            return
        elif key == Qt.Key.Key_A:
            # switch between highlight mode
            self.toggle_smart_highlighting(not self.infodock.smart_highlighting)
            return
        elif key == Qt.Key.Key_Tab:
            # decompile
            self.decompile_current_function()
            return
        elif key == Qt.Key.Key_Semicolon and event.modifiers() == Qt.KeyboardModifier.NoModifier:
            # edit the comment in place
            self.begin_inline_comment()
            return
        elif (
            key == Qt.Key.Key_Semicolon
            or key == Qt.Key.Key_Slash
            and event.modifiers() == Qt.KeyboardModifier.ControlModifier
        ):
            # add comment, with the multi-line dialog
            self.popup_comment_dialog()
            return
        elif key == Qt.Key.Key_Space:
            # switch to linear view
            self.toggle_disasm_view()
            event.accept()
            return
        elif key == Qt.Key.Key_Escape:
            # jump back
            self.jump_back()
            return
        elif key == Qt.Key.Key_C:
            self.define_code()
            return
        elif key == Qt.Key.Key_U:
            self.undefine_code()
            return

        super().keyPressEvent(event)

    def highlight_pattern_addrs(self, addrs) -> None:
        """Paint the instructions at ``addrs``, replacing any earlier pattern highlight."""
        self.presenter.highlight_pattern_addrs(addrs)

    def clear_pattern_highlight(self) -> bool:
        """Drop the pattern highlight; returns whether there was one."""
        return self.presenter.clear_pattern_highlight()

    def redraw_current_graph(self, **kwargs) -> None:
        """
        Redraw the graph currently in display.
        """
        self.presenter.redraw_current_graph(**kwargs)

    def on_screen_changed(self) -> None:
        self.presenter.on_screen_changed()

    def _reload_current_function_if_changed(self) -> None:
        self.presenter.reload_current_function_if_changed()

    def _on_cfb_event(self, **kwargs) -> None:
        self.presenter.on_cfb_event(**kwargs)

    def _refresh_linear_viewer_on_objects_added(self, objects) -> None:
        """
        Refresh the linear viewer if any of the newly added CFB objects land within the visible address range.
        """
        self.presenter.refresh_linear_viewer_on_objects_added(objects)

    def on_synchronized_cursor_address_changed(self) -> None:
        """
        Handle synchronized cursor address change event. Note that other views use real addresses while jump_to() uses
        odd addresses for ARM-THUMB mode instructions. We process the address here in case it's ARM.

        The presenter has the same method: in Qt this view is the synchronized participant, in the terminal the
        presenter is, and each guards the update with its own flag, so the body cannot be shared by delegating.
        """
        assert not self._processing_synchronized_cursor_update
        self._processing_synchronized_cursor_update = True
        try:
            if self.sync_state.cursor_address is not None:
                self.jump_to(self.sync_state.cursor_address, is_real_addr=True)
        finally:
            self._processing_synchronized_cursor_update = False

    #
    # What the presenter asks of its view
    #

    def show_control(self, control) -> None:
        """Show ``control`` (the flow graph or the linear viewer) instead of the other."""
        other = self._linear_viewer if control is self._flow_graph else self._flow_graph
        other.hide()
        control.show()

    def control_switched(self, control) -> None:
        self.focus_control(control)

    def focus_control(self, control) -> None:  # pylint:disable=no-self-use
        control.setFocus()

    def set_status_function(self, func) -> None:
        self._statusbar.function = func

    def show_instruction(self, insn_addr, insn_pos=None, use_animation: bool | None = None) -> None:
        self.presenter.show_instruction(insn_addr, insn_pos=insn_pos, use_animation=use_animation)

    #
    # UI
    #

    def append_view_menu_actions(self, menu: QMenu) -> None:
        """
        Append a separator and general QActions for this view to a given context menu.
        """
        menu.addSeparator()
        menu.addMenu(self.get_synchronize_with_submenu())

    def contextMenuEvent(self, event: PySide6.QtGui.QContextMenuEvent) -> None:  # pylint: disable=unused-argument
        """
        Display view context menu.
        """
        mnu = QMenu(self)
        mnu.addMenu(self.get_synchronize_with_submenu())
        mnu.exec_(QCursor.pos())

    def instruction_context_menu(self, insn, pos) -> None:
        self._insn_addr_on_context_menu = insn.addr

        # pass in the instruction address
        self._insn_menu.insn_addr = insn.addr
        self._update_resume_cfg_entries(self._insn_menu, insn.addr)
        # pop up the menu
        mnu = self._insn_menu.qmenu(
            extra_entries=list(self.workspace.plugins.build_context_menu_insn(insn)), cached=False
        )
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)

        self._insn_addr_on_context_menu = None

    def label_context_menu(self, addr: int, pos) -> None:
        self._label_menu.addr = addr
        self._update_resume_cfg_entries(self._label_menu, addr)
        mnu = self._label_menu.qmenu(
            extra_entries=list(self.workspace.plugins.build_context_menu_label(addr)), cached=False
        )
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)

    def unknown_block_context_menu(self, addr: int, pos) -> None:
        """
        Display a context menu for undefined bytes in the linear view.
        """
        self._unknown_menu.addr = addr
        self._update_resume_cfg_entries(self._unknown_menu, addr)
        mnu = self._unknown_menu.qmenu(cached=False)
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)

    def _update_resume_cfg_entries(self, menu, addr: int) -> None:
        """
        Enable or disable the resume-CFG-recovery entries of the given context menu based on the current state.
        """
        self.presenter.update_resume_cfg_entries(menu, addr)

    def resume_cfg_from(self, addr: int) -> None:
        self.presenter.resume_cfg_from(addr)

    def resume_cfg_full(self) -> None:
        self.presenter.resume_cfg_full()

    def rename_selected_object(self) -> None:
        """
        Opens dialog for renaming the currently selected QBlockCodeObj
        """
        obj = self.infodock.selected_block_tree_node.am_obj
        if isinstance(obj, QVariableObj):
            dlg = RenameDialog("Rename Variable", obj.obj.name, self)
            dlg.exec_()
            if dlg.result is not None:
                obj.obj.name = dlg.result
                self._current_view.refresh()

    def define_code(self) -> None:
        """
        Redefine selected data as code
        """
        self.presenter.define_code()

    def undefine_code(self) -> None:
        """
        Undefine selected instruction as code, mark it as data
        """
        self.presenter.undefine_code()

    def get_context_menu_for_selected_object(self) -> Menu | QMenu | None:
        """
        Returns the menu for the currently selected block tree node
        """
        obj = self.infodock.selected_block_tree_node.am_obj
        if isinstance(obj, tuple) and len(obj) == 2 and obj[0] == "func_name":
            self._label_menu.addr = obj[1]
            return self._label_menu
        return self.presenter.get_context_menu_for_selected_object()

    def get_selected_operand_info(self):
        return self._flow_graph.get_selected_operand_info()

    def show_context_menu_for_selected_object(self) -> None:
        """
        Spawns a context menu for the currently selected QBlockCodeObj
        """
        mnu = self.get_context_menu_for_selected_object()
        if mnu is not None:
            if isinstance(mnu, Menu):
                mnu = mnu.qmenu(cached=False)
            self.append_view_menu_actions(mnu)
            mnu.exec_(QCursor.pos())

    def popup_jumpto_dialog(self) -> None:
        JumpTo(self, parent=self).show()

    def popup_rename_label_dialog(self) -> None:
        label_addr_tpl = self._address_in_selection()
        if label_addr_tpl is None:
            return

        type_, label_addr = label_addr_tpl
        dialog = RenameLabel(self, label_addr, parent=self, full_refresh=type_ == "operand")
        dialog.exec_()

    def popup_comment_dialog(self) -> None:
        comment_addr = self._instruction_address_in_selection()
        if comment_addr is None:
            return

        dialog = SetComment(self.workspace, comment_addr, parent=self)
        dialog.exec_()

    def begin_inline_comment(self, addr: int | None = None) -> QInlineCommentEditor | None:
        """
        Start editing the comment at ``addr`` in place. Multi-line comments fall back to the dialog,
        which is the only editor that can handle them.
        """
        if addr is None:
            addr = self._comment_address_in_selection()
        if addr is None:
            return None

        kb = self.instance.kb
        text = "" if kb is None else kb.comments.get(addr, "")
        if "\n" in text:
            self._insn_addr_on_context_menu = addr
            try:
                self.popup_comment_dialog()
            finally:
                self._insn_addr_on_context_menu = None
            return None

        if self._inline_comment_editor is not None:
            self._inline_comment_editor.cancel()

        editor = QInlineCommentEditor(self.current_graph, addr, text, self._commit_inline_comment)
        rect = self.current_graph.instruction_widget_rect(addr)
        if rect is None:
            pos = QPoint(0, 0)
            width = 0
        else:
            pos = QPoint(rect.left(), rect.top())
            width = max(rect.width(), 0)
        editor.show_at(pos, width)
        self._inline_comment_editor = editor
        return editor

    def set_function_comment(self, addr: int | None = None) -> None:
        """
        Edit the comment shown as a header block above the containing function.
        """
        self.presenter.set_function_comment(addr)

    def toggle_repeatable_comment(self, addr: int | None = None) -> None:
        """
        Flip the comment at ``addr`` between repeatable and its default kind.
        """
        self.presenter.toggle_repeatable_comment(addr)

    def toggle_bookmark_at_selection(self) -> None:
        self.presenter.toggle_bookmark_at_selection()

    def popup_newstate_dialog(self) -> None:
        addr = self._instruction_address_in_selection()
        if addr is None:
            return

        dialog = NewState(self.workspace, self.instance, addr=addr, create_simgr=True, parent=self)
        dialog.exec_()

    def popup_hook_dialog(self, addr: int | None = None) -> None:
        addr = addr or self._instruction_address_in_selection()

        if addr is None:
            return

        dialog = HookDialog(self.workspace, addr=addr, parent=self)
        dialog.exec_()

    def popup_func_doc_dialog(self, instr_addr) -> None:
        """
        Spawns a popup dialog for the currently selected call instruction func_docs
        """
        if self._flow_graph is None:
            return
        block = self._flow_graph._insaddr_to_block.get(instr_addr, None)
        if block:
            found = func_doc_target(block.addr_to_insns[instr_addr])
            if found is None:
                return
            target, name, doc_tuple = found
            dialog = FuncDocDialog(self.instance, addr=target, name=name, doc_tuple=doc_tuple, parent=self)
            dialog.show()

    def popup_dependson_dialog(self, addr: int | None = None, use_operand: bool = False, func: bool = False):
        if use_operand:
            r = self._flow_graph.get_selected_operand_info()
            if r is not None:
                _, addr, operand = r
            else:
                GlobalInfo.ui_services.message("critical", "No operand", "Please select an operand first.")
                return
        else:
            if addr is None:
                raise ValueError("No address is provided.")  # this is a programming error
            operand = None

        # if a function target is selected, switch to function mode
        if operand is not None and not func and operand._branch_target is not None and operand._is_target_func:
            func = True
            addr = operand._branch_target

        if func:
            # attempt to pass in a function
            try:
                the_func = self.instance.kb.functions.get_by_addr(addr)
            except KeyError:
                the_func = None
        else:
            the_func = None

        dependson = DependsOn(addr, operand, func=the_func, parent=self)
        dependson.exec_()

        if dependson.location is not None and dependson.arg is not None:
            # track function argument
            self.workspace._main_window.run_dependency_analysis(
                func_addr=addr,
                func_arg_idx=dependson.arg,
            )

    def parse_operand_and_popup_xref_dialog(self, ins_addr, operand) -> None:
        self.presenter.parse_operand_and_popup_xref_dialog(ins_addr, operand)

    def popup_xref_dialog(self, addr: int | None = None, variable=None, dst_addr=None) -> None:
        if variable is not None:
            dialog = XRefDialog(
                addr=addr,
                variable_manager=self.variable_manager,
                variable=variable,
                instance=self.instance,
                disassembly_view=self,
                parent=self,
            )
        else:
            dialog = XRefDialog(
                addr=addr,
                xrefs_manager=self.instance.project.kb.xrefs,
                dst_addr=dst_addr,
                instance=self.instance,
                disassembly_view=self,
                parent=self,
            )
        dialog.exec_()

    def popup_patch_dialog(self) -> None:
        dlg = AssemblePatchDialog(self._insn_addr_on_context_menu, self.instance, self)
        dlg.exec_()

    #
    # Public methods
    #

    def toggle_disasm_view(self, prefer: bool = True) -> None:
        self.presenter.toggle_disasm_view(prefer)

    def display_disasm_graph(self, prefer: bool = True) -> None:
        self.presenter.display_disasm_graph(prefer)

    def display_linear_viewer(self, prefer: bool = True) -> None:
        self.presenter.display_linear_viewer(prefer)

    def display_function(self, function, send_event=True) -> None:
        self.presenter.display_function(function, send_event=send_event)

    def decompile_current_function(self) -> None:
        self.presenter.decompile_current_function()

    def toggle_show_minimap(self, show_minimap: bool | None = None) -> None:
        """
        Toggle minimap display preference
        """
        self.presenter.toggle_show_minimap(show_minimap)

    def toggle_smart_highlighting(self, enabled: bool | None = None) -> None:
        """
        Toggle between the smart highlighting mode and the text-based highlighting mode.
        """
        self.presenter.toggle_smart_highlighting(enabled)

    def toggle_show_address(self, show_address: bool | None = None) -> None:
        """
        Toggle whether addresses are shown on disassembly graph.
        """
        self.presenter.toggle_show_address(show_address)

    def toggle_show_variable(self, show_variable: bool | None = None) -> None:
        """
        Toggle whether variables are shown on disassembly graph.
        """
        self.presenter.toggle_show_variable(show_variable)

    def toggle_show_variable_identifier(self, show_ident: bool | None = None) -> None:
        """
        Toggle whether variable identifiers are shown on disassembly graph.
        """
        self.presenter.toggle_show_variable_identifier(show_ident)

    def toggle_show_exception_edges(self, show_exception_edges: bool | None = None) -> None:
        """
        Toggle whether exception edges and the nodes that are only reachable through exception edges should be shown
        or not.

        :param bool show_exception_edges:   Whether exception edges should be shown or not.
        :return:                            None
        """
        self.presenter.toggle_show_exception_edges(show_exception_edges)

    def jump_to(self, addr: int, src_ins_addr=None, use_animation: bool = False, is_real_addr: bool = False) -> bool:
        return self.presenter.jump_to(
            addr, src_ins_addr=src_ins_addr, use_animation=use_animation, is_real_addr=is_real_addr
        )

    def jump_back(self) -> None:
        self.presenter.jump_back()

    def jump_forward(self) -> None:
        self.presenter.jump_forward()

    def jump_to_history_position(self, pos: int) -> None:
        self.presenter.jump_to_history_position(pos)

    def select_label(self, label_addr) -> None:
        self.presenter.select_label(label_addr)

    def rename_label(self, addr: int, new_name: str, is_func: bool = False, full_refresh: bool = False) -> None:
        self.presenter.rename_label(addr, new_name, is_func=is_func, full_refresh=full_refresh)

    def avoid_addr_in_exec(self, addr: int) -> None:
        self.workspace._get_or_create_view("symexec", SymexecView).avoid_addr_in_exec(addr)

    def find_addr_in_exec(self, addr: int) -> None:
        self.workspace._get_or_create_view("symexec", SymexecView).find_addr_in_exec(addr)

    def run_induction_variable_analysis(self) -> None:
        self.presenter.run_induction_variable_analysis()

    def fetch_qblock_annotations(self, qblock):
        addr_to_annotations = defaultdict(list)
        if self.instance.project.am_none:
            # the project may be momentarily unset while a binary is being loaded or closed
            return QBlockAnnotations(addr_to_annotations, parent=qblock, disasm_view=self)
        plugins = self.workspace.plugins
        for annotations_ in plugins.build_qblock_annotations(qblock):
            addr_to_annotations[annotations_.addr].append(annotations_)
        # neutral marks from plugins written for both frontends
        for mark in plugins.block_marks(qblock.addr, self):
            if mark.addr is not None:
                addr_to_annotations[mark.addr].append(QMarkAnnotation(mark.addr, mark))
        for addr in qblock.addr_to_insns:
            for mark in plugins.decorate_insn(addr, self):
                addr_to_annotations[addr].append(QMarkAnnotation(addr, mark))
            if addr in self.instance.project._sim_procedures:
                hook_annotation = QHookAnnotation(addr)
                addr_to_annotations[addr].append(hook_annotation)
            view = self.workspace.view_manager.first_view_in_category("symexec")
            if view is not None:
                qsimgrs = view._simgrs
                if addr in qsimgrs.find_addrs:
                    addr_to_annotations[addr].append(QFindAddrAnnotation(addr, qsimgrs))
                if addr in qsimgrs.avoid_addrs:
                    addr_to_annotations[addr].append(QAvoidAddrAnnotation(addr, qsimgrs))
            for bp in self.instance.breakpoint_mgr.get_breakpoints_at(addr):
                addr_to_annotations[addr].append(QBreakAnnotation(bp))

        return QBlockAnnotations(addr_to_annotations, parent=qblock, disasm_view=self)

    #
    # Find in view: the presenter's, with the Qt find bar
    #

    def show_find_bar(self) -> None:
        """
        Open the incremental find bar. In graph mode it searches the current function; in linear mode it searches every
        function with at least one instruction on the displayed page, plus the data items on the page.
        """
        self.presenter.show_find_bar()

    def find_next(self) -> None:
        self.presenter.find_next()

    def find_previous(self) -> None:
        self.presenter.find_previous()

    def _update_find_matches(self) -> None:
        self.presenter.update_find_matches()

    def _on_linear_viewport_changed(self) -> None:
        self.presenter.on_linear_viewport_changed()

    def _on_find_bar_closed(self) -> None:
        self.presenter.on_find_bar_closed()

    def update_highlight_regions_for_synchronized_views(self, **kwargs) -> None:
        """
        Highlight each selected instruction in synchronized views.
        """
        self.presenter.update_highlight_regions_for_synchronized_views(**kwargs)

    #
    # Initialization
    #

    def _init_widgets(self) -> None:
        self._linear_viewer = QLinearDisassembly(self.instance, self, parent=self)
        self._flow_graph = QDisassemblyGraph(self.instance, self, parent=self)
        self._statusbar = QDisasmStatusBar(self, parent=self)

        self._find_bar = QFindBar(self, modes=[self.FIND_MODE_TEXT, self.FIND_MODE_TEXT_INSN, self.FIND_MODE_BYTES])
        self.presenter.find_bar = self._find_bar
        self._find_bar.query_changed.connect(self._update_find_matches)
        self._find_bar.find_next.connect(self.find_next)
        self._find_bar.find_previous.connect(self.find_previous)
        self._find_bar.closed.connect(self._on_find_bar_closed)
        self._linear_viewer.viewport_changed.connect(self._on_linear_viewport_changed)

        vlayout = QVBoxLayout()
        vlayout.addWidget(self._statusbar)
        vlayout.addWidget(self._find_bar)
        vlayout.addWidget(self._flow_graph)
        vlayout.addWidget(self._linear_viewer)
        vlayout.setSpacing(0)
        vlayout.setContentsMargins(0, 0, 0, 0)

        vlayout.setStretchFactor(self._flow_graph, 1)
        vlayout.setStretchFactor(self._linear_viewer, 1)
        vlayout.setStretchFactor(self._statusbar, 0)

        hlayout = QHBoxLayout()
        hlayout.addLayout(vlayout)
        hlayout.setSpacing(20)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

        self.display_disasm_graph()

        self.workspace.plugins.instrument_disassembly_view(self)

    def _init_menus(self) -> None:
        # the menus call this view, which forwards what is not Qt to the presenter
        self._insn_menu = DisasmInsnContextMenu(self)
        self._label_menu = DisasmLabelContextMenu(self)
        self._unknown_menu = DisasmUnknownContextMenu(self)

    def _init_shortcuts(self) -> None:
        for sequence, handler in [
            (QKeySequence.StandardKey.Find, self.show_find_bar),
            (QKeySequence(Qt.Key.Key_F3), self.find_next),
            (QKeySequence("Shift+F3"), self.find_previous),
        ]:
            shortcut = QShortcut(sequence, self, handler)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _register_events(self) -> None:
        self.presenter.register_events()

    def _unregister_events(self) -> None:
        self.presenter.unregister_events()

    def closeEvent(self, event) -> None:
        self._unregister_events()
        super().closeEvent(event)

    #
    # Private methods
    #

    def _display_function(self, the_func, send_event=True) -> None:
        self.presenter.display_function_without_history(the_func, send_event=send_event)

    def _jump_to(self, addr: int, use_animation: bool = False, is_real_addr: bool = False) -> bool:
        return self.presenter.jump_to_without_history(addr, use_animation=use_animation, is_real_addr=is_real_addr)

    #
    # Utils
    #

    def address_in_selection(self) -> tuple[str, int] | None:
        """What the selection points at, as ``(kind, address)``; the context menus ask for it."""
        return self._address_in_selection()

    def _address_in_selection(self) -> tuple[str, int] | None:
        return self.presenter.address_in_selection()

    def _comment_address_in_selection(self) -> int | None:
        """
        The address to comment on: the selected instruction, or the function whose name is selected.
        """
        return self.presenter.comment_address_in_selection()

    def _commit_inline_comment(self, addr: int, text: str) -> None:
        self._inline_comment_editor = None
        self.presenter.set_comment(addr, text)

    def _instruction_address_in_selection(self) -> int | None:
        return self.presenter.instruction_address_in_selection()

    def _get_instruction_size(self, addr: int) -> int | None:
        return self.presenter.get_instruction_size(addr)

    @property
    def flow_graph(self):
        return self._flow_graph

    @property
    def linear_viewer(self):
        return self._linear_viewer
