from __future__ import annotations

import bisect
import contextlib
import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from angr.block import Block
from angr.knowledge_plugins.cfg import MemoryData
from archinfo.arch_arm import get_real_address_if_arm, is_arm_arch
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QAction, QCursor, QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QHBoxLayout, QMenu, QMessageBox, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.data.function_graph import FunctionGraph
from angrmanagement.data.highlight_region import SynchronizedHighlightRegion
from angrmanagement.data.search import BytePattern, Searcher, SearchError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.commands import ViewCommand
from angrmanagement.logic.disassembly import InfoDock, JumpHistory
from angrmanagement.logic.threads import needs_gui_thread
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
from angrmanagement.ui.widgets.qinst_annotation import QBreakAnnotation, QHookAnnotation
from angrmanagement.utils import get_label_text, locate_function

from .view import SynchronizedFunctionView

if TYPE_CHECKING:
    import re

    import PySide6
    from angr.knowledge_plugins import VariableManager
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance, ObjectContainer
    from angrmanagement.logic.disassembly.info_dock import OperandDescriptor
    from angrmanagement.ui.workspace import Workspace


_l = logging.getLogger(__name__)


class DisassemblyView(SynchronizedFunctionView):
    """
    Disassembly View
    """

    view_visibility_changed = Signal()
    disassembly_level_changed = Signal(DisassemblyLevel)

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("disassembly", workspace, default_docking_position, instance)

        self.base_caption = "Disassembly"
        self._disassembly_level = DisassemblyLevel.MachineCode
        self._show_minimap: bool = True
        self._show_address = True
        self._show_variable = True
        # whether we want to show identifier or not
        self._show_variable_ident = False
        # whether we want to show exception edges and all nodes that are only reachable through exception edges
        self._show_exception_edges = True

        self._prefer_graph = True
        self._current_view: QLinearDisassembly | QDisassemblyGraph | None = None

        self._statusbar = None
        self.jump_history: JumpHistory = JumpHistory()
        self.infodock = InfoDock(self)
        self._variable_recovery_flavor = "fast"
        self.variable_manager: VariableManager | None = None

        self._insn_menu: DisasmInsnContextMenu | None = None
        self._label_menu: DisasmLabelContextMenu | None = None

        self._insn_addr_on_context_menu = None

        self.width_hint = 800
        self.height_hint = 800

        self._find_bar: QFindBar | None = None
        self._find_matches: list[tuple[int, str]] = []
        self._find_data_matches: dict[int, int] = {}  # match addr -> owning data item addr
        self._find_matches_capped: bool = False
        self._find_index: int = -1
        self._find_highlighted: bool = False
        self._find_text_cache: dict[int, list[tuple[int, str, bytes]]] = {}
        self._in_find_refresh: bool = False

        self._init_widgets()
        self._init_menus()
        self._register_events()
        self._init_shortcuts()

    @classmethod
    def register_commands(cls, workspace: Workspace) -> None:
        """
        Register commands that can be run for this view.
        """
        workspace.command_manager.register_commands(
            [
                ViewCommand("disassembly_view_" + action.__name__, "Disassembly: " + caption, action, cls, workspace)
                for caption, action in [
                    ("Comment", cls.popup_comment_dialog),
                    ("Jump Back", cls.jump_back),
                    ("Jump Forward", cls.jump_forward),
                    ("Jump To", cls.popup_jumpto_dialog),
                    ("Toggle Addresses", cls.toggle_show_address),
                    ("Toggle Exception Edges", cls.toggle_show_exception_edges),
                    ("Toggle Graph/Linear view", cls.toggle_disasm_view),
                    ("Toggle Minimap", cls.toggle_show_minimap),
                    ("Toggle Smart Highlighting", cls.toggle_smart_highlighting),
                    ("Toggle Variable Identifiers", cls.toggle_show_variable_identifier),
                    ("Toggle Variables", cls.toggle_show_variable),
                    ("Find", cls.show_find_bar),
                    ("Find Next", cls.find_next),
                    ("Find Previous", cls.find_previous),
                    ("View AIL", cls.set_disassembly_level_ail),
                    ("View Lifter IR", cls.set_disassembly_level_lifter_ir),
                    ("View Machine Code", cls.set_disassembly_level_machine_code),
                ]
            ]
        )

    @property
    def disassembly_level(self):
        return self._disassembly_level

    @needs_gui_thread
    def set_disassembly_level(self, level: DisassemblyLevel) -> None:
        self._disassembly_level = level
        self._flow_graph.set_disassembly_level(level)
        self._linear_viewer.set_disassembly_level(level)
        self.disassembly_level_changed.emit(level)
        self.redraw_current_graph()

    def set_disassembly_level_ail(self) -> None:
        self.set_disassembly_level(DisassemblyLevel.AIL)

    def set_disassembly_level_lifter_ir(self) -> None:
        self.set_disassembly_level(DisassemblyLevel.LifterIR)

    def set_disassembly_level_machine_code(self) -> None:
        self.set_disassembly_level(DisassemblyLevel.MachineCode)

    def reload(self) -> None:
        old_infodock = self.infodock.copy()

        self.infodock.initialize()

        # Reload the current graph to make sure it gets the latest information, such as variables.
        self._reload_current_function_if_changed()
        self._current_view.reload(old_infodock=old_infodock)

    def refresh(self) -> None:
        self._current_view.refresh()

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
        return self._show_minimap

    @property
    def smart_highlighting(self):
        if self._flow_graph is None:
            return False
        if self.infodock is None:
            return False
        return self.infodock.smart_highlighting

    @property
    def show_address(self):
        return self._show_address

    @property
    def show_variable(self):
        return self._show_variable

    @property
    def show_variable_identifier(self):
        return self._show_variable_ident

    @property
    def show_exception_edges(self):
        return self._show_exception_edges

    @property
    def variable_recovery_flavor(self):
        return self._variable_recovery_flavor

    @variable_recovery_flavor.setter
    def variable_recovery_flavor(self, v) -> None:
        if v in ("fast", "accurate") and v != self._variable_recovery_flavor:
            self._variable_recovery_flavor = v
            # TODO: Rerun the variable recovery analysis and update the current view

    @property
    def current_graph(self) -> QLinearDisassembly | QDisassemblyGraph:
        """
        Return the current disassembly control, either linear viewer or flow graph.

        :return:    Linear viewer or flow graph.
        """
        return self._current_view

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
        if not self.function.am_none and self.function.addr == func_addr:
            self.reload()

    def on_variable_recovered(self, func_addr: int) -> None:
        if not self.function.am_none and self.function.addr == func_addr:
            self.reload()

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
        elif (
            key == Qt.Key.Key_Semicolon
            or key == Qt.Key.Key_Slash
            and event.modifiers() == Qt.KeyboardModifier.ControlModifier
        ):
            # add comment
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

    def redraw_current_graph(self, **kwargs) -> None:  # pylint: disable=unused-argument
        """
        Redraw the graph currently in display.

        :return:    None
        """
        self._current_view.redraw()

    def on_screen_changed(self) -> None:
        self._current_view.refresh()

    def _reload_current_function_if_changed(self) -> None:
        if self._flow_graph.function_graph is not None:
            func_addr = self._flow_graph.function_graph.function.addr

            try:
                func = self.instance.kb.functions.get_by_addr(func_addr)
            except KeyError:
                func = None

            if self._flow_graph.function_graph.function is not func:
                self._display_function(func)

            if func is None:
                self._jump_to(func_addr)

    def _on_cfb_event(self, **kwargs) -> None:
        if not kwargs:
            self._find_text_cache.clear()
            if self.instance.project.am_none:
                # the binary was closed: clear both the graph and linear viewer
                self.function.am_obj = None
                self._flow_graph.function_graph = None
                self._linear_viewer.reload()
                return
            self._reload_current_function_if_changed()
            self._linear_viewer.reload()

    def on_synchronized_cursor_address_changed(self) -> None:
        """
        Handle synchronized cursor address change event. Note that other views use real addresses while jump_to() uses
        odd addresses for ARM-THUMB mode instructions. We process the address here in case it's ARM.
        """
        assert not self._processing_synchronized_cursor_update
        self._processing_synchronized_cursor_update = True
        try:
            if self.sync_state.cursor_address is not None:
                self.jump_to(self.sync_state.cursor_address, is_real_addr=True)
        finally:
            self._processing_synchronized_cursor_update = False

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
        # pop up the menu
        mnu = self._insn_menu.qmenu(
            extra_entries=list(self.workspace.plugins.build_context_menu_insn(insn)), cached=False
        )
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)

        self._insn_addr_on_context_menu = None

    def label_context_menu(self, addr: int, pos) -> None:
        self._label_menu.addr = addr
        mnu = self._label_menu.qmenu(
            extra_entries=list(self.workspace.plugins.build_context_menu_label(addr)), cached=False
        )
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)

    def rename_selected_object(self) -> None:
        """
        Opens dialog for renaming the currently selected QBlockCodeObj
        """
        obj = self.infodock.selected_block_tree_node
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
        if self.infodock.selected_labels:
            self.workspace.define_code(next(iter(self.infodock.selected_labels)))

    def undefine_code(self) -> None:
        """
        Undefine selected instruction as code, mark it as data
        """
        if self.infodock.selected_insns:
            self.workspace.undefine_code(next(iter(self.infodock.selected_insns)))

    def get_context_menu_for_selected_object(self) -> Menu | QMenu | None:
        """
        Returns a QMenu object for the currently selected QBlockCodeObj
        """
        obj = self.infodock.selected_block_tree_node
        if isinstance(obj, tuple) and len(obj) == 2:
            ty, addr = obj
            if ty == "func_name":
                self._label_menu.addr = addr
                return self._label_menu
        if isinstance(obj, QVariableObj):
            rename_act = QAction("Re&name", self)
            rename_act.triggered.connect(self.rename_selected_object)
            mnu = QMenu()
            mnu.addActions([rename_act])
            return mnu
        else:
            return None

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
            instr = block.addr_to_insns[instr_addr]
            if instr is None or instr.insn.type != "call":
                return
            out_targets = instr.out_branch.targets
            if len(out_targets) != 1:
                return

            target = next(iter(out_targets))
            operand = instr.get_operand(0)

            doc_tuple = GlobalInfo.library_docs.get_docstring_for_func_name(operand.text)
            if doc_tuple is None:
                doc_string = f"Cannot find local documentation for function {operand.text}."
                url = "http://"
                ftype = "<>"
                doc_tuple = (doc_string, url, ftype)
            dialog = FuncDocDialog(self.instance, addr=target, name=operand.text, doc_tuple=doc_tuple, parent=self)
            dialog.show()

    def popup_dependson_dialog(self, addr: int | None = None, use_operand: bool = False, func: bool = False):
        if use_operand:
            r = self._flow_graph.get_selected_operand_info()
            if r is not None:
                _, addr, operand = r
            else:
                QMessageBox.critical(
                    self,
                    "No operand",
                    "Please select an operand first.",
                    buttons=QMessageBox.StandardButton.Ok,
                )
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
        if operand is not None:
            if operand.variable is not None:
                # Display cross references to this variable
                self.popup_xref_dialog(addr=ins_addr, variable=operand.variable)
            elif operand.is_constant:
                # Display cross references to an address
                self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_value)
            elif operand.is_constant_memory:
                # Display cross references to an address
                self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_memory_value)

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
        if self._flow_graph.isHidden():
            # Show flow graph
            self.display_disasm_graph(prefer)
        else:
            # Show linear viewer
            self.display_linear_viewer(prefer)

    @needs_gui_thread
    def display_disasm_graph(self, prefer: bool = True) -> None:
        if prefer:
            self._prefer_graph = True

        self._linear_viewer.hide()
        self._current_view = self._flow_graph
        self._flow_graph.show()

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self._jump_to(next(iter(self.infodock.selected_insns)))
        elif self.function.am_obj is not None:
            self._flow_graph.show_instruction(self.function.addr)

        self._flow_graph.setFocus()
        self.view_visibility_changed.emit()
        self._flow_graph.refresh()
        self._refresh_find_matches_for_view_switch()

    @needs_gui_thread
    def display_linear_viewer(self, prefer: bool = True) -> None:
        if prefer:
            self._prefer_graph = False

        self._flow_graph.hide()
        self._current_view = self._linear_viewer
        self._linear_viewer.show()

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self._linear_viewer.show_instruction(next(iter(self.infodock.selected_insns)))
        elif self.function.am_obj is not None:
            self._linear_viewer.show_instruction(self.function.addr)

        self._linear_viewer.setFocus()
        self.view_visibility_changed.emit()
        self._linear_viewer.refresh()
        self._refresh_find_matches_for_view_switch()

    def display_function(self, function, send_event=True) -> None:
        if function is None:
            return
        self.jump_history.jump_to(function.addr)
        self._display_function(function, send_event=send_event)

    def decompile_current_function(self) -> None:
        if self.function.am_obj is not None:
            try:
                curr_ins = next(iter(self.infodock.selected_insns))
            except StopIteration:
                curr_ins = None

            self.workspace.decompile_function(self.function.am_obj, curr_ins=curr_ins)

    def toggle_show_minimap(self, show_minimap: bool | None = None) -> None:
        """
        Toggle minimap display preference
        """
        if show_minimap is None:
            show_minimap = not self._show_minimap
        self._show_minimap = show_minimap
        self._current_view.refresh()

    def toggle_smart_highlighting(self, enabled: bool | None = None) -> None:
        """
        Toggle between the smart highlighting mode and the text-based highlighting mode.
        """
        if enabled is None:
            enabled = not self.infodock.smart_highlighting
        self.infodock.smart_highlighting = enabled
        self._flow_graph.refresh()
        self._linear_viewer.refresh()

    def toggle_show_address(self, show_address: bool | None = None) -> None:
        """
        Toggle whether addresses are shown on disassembly graph.
        """
        if show_address is None:
            show_address = not self._show_address
        self._show_address = show_address
        self._current_view.refresh()

    def toggle_show_variable(self, show_variable: bool | None = None) -> None:
        """
        Toggle whether variables are shown on disassembly graph.
        """
        if show_variable is None:
            show_variable = not self._show_variable
        self._show_variable = show_variable
        self._current_view.refresh()

    def toggle_show_variable_identifier(self, show_ident: bool | None = None) -> None:
        """
        Toggle whether variable identifiers are shown on disassembly graph.
        """
        if show_ident is None:
            show_ident = not self._show_variable_ident
        self._show_variable_ident = show_ident
        self._current_view.refresh()

    def toggle_show_exception_edges(self, show_exception_edges: bool | None = None) -> None:
        """
        Toggle whether exception edges and the nodes that are only reachable through exception edges should be shown
        or not.

        :param bool show_exception_edges:   Whether exception edges should be shown or not.
        :return:                            None
        """

        if show_exception_edges != self._show_exception_edges:
            self._show_exception_edges = show_exception_edges

            # reset the function graph
            if self._flow_graph.function_graph is not None:
                self._flow_graph.function_graph.exception_edges = show_exception_edges
                self._flow_graph.function_graph.clear_cache()
                self._flow_graph.reload()

    def jump_to(self, addr: int, src_ins_addr=None, use_animation: bool = False, is_real_addr: bool = False) -> bool:
        # Do not jump if addr is not in the binary
        if not self.instance.project.am_none and self.instance.project.loader.find_object_containing(addr) is None:
            return False

        # Record the current instruction address
        if src_ins_addr is not None:
            self.jump_history.record_address(src_ins_addr)

        self.jump_history.jump_to(addr)
        self._jump_to(addr, use_animation=use_animation, is_real_addr=is_real_addr)

        return True

    def jump_back(self) -> None:
        addr = self.jump_history.backtrack()
        if addr is not None:
            self._jump_to(addr, use_animation=False)

    def jump_forward(self) -> None:
        addr = self.jump_history.forwardstep()
        if addr is not None:
            self._jump_to(addr, use_animation=False)

    def jump_to_history_position(self, pos: int) -> None:
        addr = self.jump_history.step_position(pos)
        if addr is not None:
            self._jump_to(addr, use_animation=False)

    def select_label(self, label_addr) -> None:
        self.infodock.select_label(label_addr)

    def rename_label(self, addr: int, new_name: str, is_func: bool = False, full_refresh: bool = False) -> None:
        if self._flow_graph.disasm is not None:
            is_renaming = False

            kb = self._flow_graph.disasm.kb
            if is_func:
                func = kb.functions.get_by_addr(addr)
                is_renaming = True
                if new_name:
                    func.name = new_name
                else:
                    # restore to the default name
                    func.name = f"sub_{addr:x}"
            else:
                if new_name == "":
                    if addr in kb.labels:
                        del kb.labels[addr]
                else:
                    if addr in kb.labels:
                        is_renaming = True
                    kb.labels[addr] = new_name

            # callback first
            if self.instance.label_rename_callback:
                self.instance.label_rename_callback(addr=addr, new_name=new_name)

            if full_refresh:
                # redraw the entire graph. required if a data address is renamed.
                self._flow_graph.refresh()
            else:
                # redraw the current block
                self._flow_graph.update_label(addr, is_renaming=is_renaming)

    def avoid_addr_in_exec(self, addr: int) -> None:
        self.workspace._get_or_create_view("symexec", SymexecView).avoid_addr_in_exec(addr)

    def find_addr_in_exec(self, addr: int) -> None:
        self.workspace._get_or_create_view("symexec", SymexecView).find_addr_in_exec(addr)

    def run_induction_variable_analysis(self) -> None:
        if self._flow_graph.induction_variable_analysis:
            self._flow_graph.induction_variable_analysis = None
        else:
            analyses = self.instance.project.analyses
            ana = analyses.AffineRelationAnalysis(self._flow_graph._function_graph.function)
            self._flow_graph.induction_variable_analysis = ana
        self._flow_graph.refresh()

    def fetch_qblock_annotations(self, qblock):
        addr_to_annotations = defaultdict(list)
        if self.instance.project.am_none:
            # the project may be momentarily unset while a binary is being loaded or closed
            return QBlockAnnotations(addr_to_annotations, parent=qblock, disasm_view=self)
        for annotations_ in self.workspace.plugins.build_qblock_annotations(qblock):
            addr_to_annotations[annotations_.addr].append(annotations)
        for addr in qblock.addr_to_insns:
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
    # Find in view
    #

    # highlighting every hit of a very common mnemonic would repaint the whole function
    FIND_HIGHLIGHT_LIMIT = 512

    FIND_MODE_TEXT = "Text"
    FIND_MODE_TEXT_INSN = "Text (instruction only)"
    FIND_MODE_BYTES = "Byte pattern"

    def show_find_bar(self) -> None:
        """
        Open the incremental find bar. In graph mode it searches the current function; in linear mode it searches every
        function with at least one instruction on the displayed page, plus the data items on the page.
        """
        self._find_text_cache.clear()
        self._find_bar.activate()
        self._update_find_matches()

    def find_next(self) -> None:
        self._step_find_match(1)

    def find_previous(self) -> None:
        self._step_find_match(-1)

    def _find_scope_functions(self) -> list[Function]:
        if self.instance.project.am_none:
            return []
        if self._current_view is self._linear_viewer:
            functions = []
            for func_addr in self._linear_viewer.visible_function_addrs:
                with contextlib.suppress(KeyError):
                    functions.append(self.instance.kb.functions.get_by_addr(func_addr))
            return functions
        func = self.function.am_obj
        return [func] if func is not None else []

    def _function_details(self, searcher: Searcher, func: Function) -> list[tuple[int, str, bytes]]:
        cached = self._find_text_cache.get(func.addr)
        if cached is None:
            cached = list(searcher.iter_instruction_details(func))
            self._find_text_cache[func.addr] = cached
        return cached

    def _visible_data_items(self) -> list[tuple[int, bytes, str]]:
        """
        ``(address, bytes, label)`` for every data item on the displayed linear page.
        """
        if self._current_view is not self._linear_viewer or self.instance.project.am_none:
            return []
        items = []
        for addr, memory_data in self._linear_viewer.visible_memory_data:
            data = b""
            if memory_data.content:
                data = bytes(memory_data.content)[: memory_data.size or None]
            if memory_data.size and len(data) < memory_data.size:
                with contextlib.suppress(KeyError):
                    data += bytes(
                        self.instance.project.loader.memory.load(addr + len(data), memory_data.size - len(data))
                    )
            if not data:
                continue
            items.append((addr, data, get_label_text(addr, self.instance.kb) or ""))
        return items

    def _collect_text_matches(
        self, regex: re.Pattern, instructions_only: bool
    ) -> tuple[list[tuple[int, str]], dict[int, int]]:
        matches: list[tuple[int, str]] = []
        data_matches: dict[int, int] = {}
        limit = Conf.find_match_limit
        searcher = Searcher(self.instance.project.am_obj, kb=self.instance.kb)
        comments = self.instance.kb.comments if not instructions_only else None
        for func in self._find_scope_functions():
            for addr, text, _ in self._function_details(searcher, func):
                comment = comments.get(addr) if comments is not None else None
                if comment:
                    text = f"{text} ; {comment}"
                if regex.search(text):
                    if len(matches) >= limit:
                        self._find_matches_capped = True
                        break
                    matches.append((addr, text))
            if self._find_matches_capped:
                break
        if not instructions_only and not self._find_matches_capped:
            for addr, data, label in self._visible_data_items():
                text = f"{label} {data.decode('latin-1')}".strip()
                if regex.search(text):
                    if len(matches) >= limit:
                        self._find_matches_capped = True
                        break
                    matches.append((addr, text))
                    data_matches[addr] = addr
        matches.sort(key=lambda match: match[0])
        return matches, data_matches

    def _collect_byte_matches(self, pattern: BytePattern) -> tuple[list[tuple[int, str]], dict[int, int]]:
        matches: list[tuple[int, str]] = []
        data_matches: dict[int, int] = {}
        limit = Conf.find_match_limit
        searcher = Searcher(self.instance.project.am_obj, kb=self.instance.kb)

        # collect the byte pieces of the scope: every instruction, plus the visible data items
        pieces: list[tuple[int, bytes, bool, str]] = []  # (addr, bytes, is_data, text)
        seen_addrs: set[int] = set()
        for func in self._find_scope_functions():
            for addr, text, raw in self._function_details(searcher, func):
                if raw and addr not in seen_addrs:
                    seen_addrs.add(addr)
                    pieces.append((addr, raw, False, text))
        for item_addr, data, _ in self._visible_data_items():
            if item_addr not in seen_addrs:
                pieces.append((item_addr, data, True, ""))
        pieces.sort(key=lambda piece: piece[0])

        # merge contiguous pieces into runs so the pattern can match across instruction and instruction/data boundaries
        runs: list[tuple[int, bytearray, list[tuple[int, bool, str]]]] = []
        for addr, raw, is_data, text in pieces:
            if runs and addr == runs[-1][0] + len(runs[-1][1]):
                runs[-1][1].extend(raw)
                runs[-1][2].append((addr, is_data, text))
            elif runs and addr < runs[-1][0] + len(runs[-1][1]):
                continue  # e.g. a block shared by two scope functions
            else:
                runs.append((addr, bytearray(raw), [(addr, is_data, text)]))

        capped = False
        seen_anchors: set[int] = set()
        for run_start, run_bytes, units in runs:
            unit_starts = [unit[0] for unit in units]
            for match_addr in pattern.finditer(bytes(run_bytes), base=run_start):
                unit_addr, is_data, text = units[bisect.bisect_right(unit_starts, match_addr) - 1]
                # instruction matches are anchored at the instruction containing the match start
                if not is_data and unit_addr in seen_anchors:
                    continue
                if len(matches) >= limit:
                    capped = True
                    break
                if is_data:
                    offset = match_addr - run_start
                    matches.append((match_addr, run_bytes[offset : offset + len(pattern)].hex(" ")))
                    data_matches[match_addr] = unit_addr
                else:
                    seen_anchors.add(unit_addr)
                    matches.append((unit_addr, text))
            if capped:
                break
        self._find_matches_capped = capped
        matches.sort(key=lambda match: match[0])
        return matches, data_matches

    def _compute_find_matches(self) -> tuple[list[tuple[int, str]], dict[int, int]] | None:
        """
        Compute the match list for the find bar's current mode and query. Returns None if the query is malformed (with
        the error flagged on the bar).
        """
        self._find_matches_capped = False
        query = self._find_bar.query
        if not query or self.instance.project.am_none:
            self._find_bar.set_error(False)
            return [], {}
        if self._find_bar.mode == self.FIND_MODE_BYTES:
            try:
                pattern = BytePattern.parse(query)
            except SearchError:
                self._find_bar.set_error(True)
                return None
            self._find_bar.set_error(False)
            return self._collect_byte_matches(pattern)
        regex = self._find_bar.compile_query(loose_whitespace=True)
        if regex is None:
            return None
        return self._collect_text_matches(regex, instructions_only=self._find_bar.mode == self.FIND_MODE_TEXT_INSN)

    def _update_find_matches(self) -> None:
        self._find_bar.set_text_options_visible(self._find_bar.mode != self.FIND_MODE_BYTES)
        self._find_index = -1
        self._find_matches = []
        self._find_data_matches = {}
        result = self._compute_find_matches()
        if result is not None:
            self._find_matches, self._find_data_matches = result
        if not self._find_matches:
            self._clear_find_highlights()
            self._find_bar.set_match_status(0, 0)
        elif self._current_view is self._linear_viewer:
            # do not move the viewport while typing; the current match starts at the first match
            # at or after the top of the page
            self._find_index = self._first_match_at_or_after_viewport_top()
            self._apply_find_highlights()
        else:
            self._step_find_match(1)

    def _on_linear_viewport_changed(self) -> None:
        """
        Re-apply the find query to the functions that are visible after the linear view scrolled.
        """
        if (
            self._find_bar is None
            or self._find_bar.isHidden()
            or self._current_view is not self._linear_viewer
            or self._in_find_refresh
            or not self._find_bar.query
        ):
            return
        self._in_find_refresh = True
        try:
            self._refresh_find_matches()
        finally:
            self._in_find_refresh = False

    def _refresh_find_matches_for_view_switch(self) -> None:
        """
        The find scope depends on the display mode, so recompute the matches when the view toggles between graph and
        linear (without navigating).
        """
        if self._find_bar is None or self._find_bar.isHidden() or not self._find_bar.query or self._in_find_refresh:
            return
        self._in_find_refresh = True
        try:
            self._refresh_find_matches()
        finally:
            self._in_find_refresh = False

    def _refresh_find_matches(self) -> None:
        result = self._compute_find_matches()
        if result is None:
            return
        current_addr = (
            self._find_matches[self._find_index][0] if 0 <= self._find_index < len(self._find_matches) else None
        )
        self._find_matches, self._find_data_matches = result
        if not self._find_matches:
            self._find_index = -1
            self._clear_find_highlights()
            self._find_bar.set_match_status(0, 0)
            return
        addrs = [addr for addr, _ in self._find_matches]
        self._find_index = (
            addrs.index(current_addr) if current_addr in addrs else self._first_match_at_or_after_viewport_top()
        )
        self._apply_find_highlights()

    def _first_match_at_or_after_viewport_top(self) -> int:
        top = self._linear_viewer.first_visible_instruction_addr
        if top is None:
            return 0
        return next((i for i, (addr, _) in enumerate(self._find_matches) if addr >= top), 0)

    def _apply_find_highlights(self) -> None:
        """Apply the highlight set and the match counter for the current match list, without moving the viewport."""
        highlighted = self._find_insn_highlight_set()
        if 0 <= self._find_index < len(self._find_matches):
            current = self._find_matches[self._find_index][0]
            if current not in self._find_data_matches:
                highlighted.add(current)
        self._find_highlighted = True
        self.infodock.unselect_all_labels()
        self.infodock.selected_insns.am_obj = highlighted
        self.infodock.selected_insns.am_event()
        self._find_bar.set_match_status(self._find_index, len(self._find_matches), capped=self._find_matches_capped)

    def _find_insn_highlight_set(self) -> set[int]:
        return {
            addr for addr, _ in self._find_matches[: self.FIND_HIGHLIGHT_LIMIT] if addr not in self._find_data_matches
        }

    def _step_find_match(self, delta: int) -> None:
        if not self._find_matches:
            self._find_bar.set_match_status(0, 0)
            return
        self._find_index = (self._find_index + delta) % len(self._find_matches)
        addr = self._find_matches[self._find_index][0]

        highlighted = self._find_insn_highlight_set()
        data_item_addr = self._find_data_matches.get(addr)
        self._find_highlighted = True
        if data_item_addr is not None:
            # a data match: highlight the data item's label, keep the instruction highlights
            self.infodock.select_label(data_item_addr)
            self.infodock.selected_insns.am_obj = highlighted
            self.infodock.selected_insns.am_event()
        else:
            highlighted.add(addr)
            self.infodock.unselect_all_labels()
            self.infodock.selected_insns.am_obj = highlighted
            self.set_synchronized_cursor_address(get_real_address_if_arm(self.instance.project.arch, addr))
            self.infodock.selected_insns.am_event(insn_addr=addr)
        # navigating may scroll the linear view, which re-applies the query and remaps _find_index
        self._current_view.show_instruction(addr, use_animation=False)
        self._find_bar.set_match_status(self._find_index, len(self._find_matches), capped=self._find_matches_capped)

    def _clear_find_highlights(self) -> None:
        if self._find_highlighted:
            self._find_highlighted = False
            self.infodock.unselect_all_instructions()
            self.infodock.unselect_all_labels()

    def _on_find_bar_closed(self) -> None:
        self._find_text_cache.clear()
        # keep only the current match selected
        if self._find_highlighted and 0 <= self._find_index < len(self._find_matches):
            addr = self._find_matches[self._find_index][0]
            self._find_highlighted = False
            if addr in self._find_data_matches:
                # the data item's label selection is the current match; drop the rest
                self.infodock.unselect_all_instructions()
            else:
                self.infodock.selected_insns.am_obj = {addr}
                self.infodock.selected_insns.am_event(insn_addr=addr)
        else:
            self._clear_find_highlights()
        self._find_matches = []
        self._find_data_matches = {}
        self._find_index = -1
        self._current_view.setFocus()

    def _on_insn_selection_changed(self, **kwargs) -> None:
        """
        In linear view, make the current function follow the selected instruction so the status bar and function-scoped
        actions refer to the function that was actually clicked.
        """
        if self._current_view is not self._linear_viewer or self.instance.project.am_none:
            return
        insn_addr = kwargs.get("insn_addr")
        if insn_addr is None:
            return
        func = None
        func_addr = self._linear_viewer.function_addr_of_instruction(insn_addr)
        if func_addr is not None:
            with contextlib.suppress(KeyError):
                func = self.instance.kb.functions.get_by_addr(func_addr)
        if func is None:
            func = locate_function(self.instance, insn_addr)
        if func is None or (not self.function.am_none and self.function.am_obj.addr == func.addr):
            return
        # update quietly: firing the container event would navigate away and clear the selection
        self.function.am_obj = func
        self._statusbar.function = func

    def update_highlight_regions_for_synchronized_views(self, **kwargs) -> None:  # pylint: disable=unused-argument
        """
        Highlight each selected instruction in synchronized views.
        """
        regions = []
        is_arm = is_arm_arch(self.instance.project.arch) if not self.instance.project.am_none else False
        for addr in self.infodock.selected_insns:
            s = self._get_instruction_size(addr)
            if s is not None:
                real_addr = addr & 0xFFFF_FFFE if is_arm else addr
                regions.append(SynchronizedHighlightRegion(real_addr, s))
        self.set_synchronized_highlight_regions(regions)

    #
    # Initialization
    #

    def _init_widgets(self) -> None:
        self._linear_viewer = QLinearDisassembly(self.instance, self, parent=self)
        self._flow_graph = QDisassemblyGraph(self.instance, self, parent=self)
        self._statusbar = QDisasmStatusBar(self, parent=self)

        self._find_bar = QFindBar(self, modes=[self.FIND_MODE_TEXT, self.FIND_MODE_TEXT_INSN, self.FIND_MODE_BYTES])
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
        self._insn_menu = DisasmInsnContextMenu(self)
        self._label_menu = DisasmLabelContextMenu(self)

    def _init_shortcuts(self) -> None:
        for sequence, handler in [
            (QKeySequence.StandardKey.Find, self.show_find_bar),
            (QKeySequence(Qt.Key.Key_F3), self.find_next),
            (QKeySequence("Shift+F3"), self.find_previous),
        ]:
            shortcut = QShortcut(sequence, self, handler)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)

    def _register_events(self) -> None:
        # redraw the current graph if instruction/operand selection changes
        self.infodock.selected_insns.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_insns.am_subscribe(self.update_highlight_regions_for_synchronized_views)
        self.infodock.selected_insns.am_subscribe(self._on_insn_selection_changed)
        self.infodock.selected_operands.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_blocks.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_block.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_edge.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_labels.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_variables.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_block_tree_node.am_subscribe(self.redraw_current_graph)
        self.workspace.current_screen.am_subscribe(self.on_screen_changed)
        self.instance.breakpoint_mgr.breakpoints.am_subscribe(self._on_breakpoints_updated)
        self.instance.cfb.am_subscribe(self._on_cfb_event)
        self.function.am_subscribe(lambda: self.display_function(self.function.am_obj, send_event=False))

    def _on_breakpoints_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.refresh()

    def _unregister_events(self) -> None:
        self.infodock.selected_insns.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_insns.am_unsubscribe(self.update_highlight_regions_for_synchronized_views)
        self.infodock.selected_insns.am_unsubscribe(self._on_insn_selection_changed)
        self.infodock.selected_operands.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_blocks.am_unsubscribe(self.redraw_current_graph)
        self.infodock.hovered_block.am_unsubscribe(self.redraw_current_graph)
        self.infodock.hovered_edge.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_labels.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_variables.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_block_tree_node.am_unsubscribe(self.redraw_current_graph)
        self.workspace.current_screen.am_unsubscribe(self.on_screen_changed)
        self.instance.breakpoint_mgr.breakpoints.am_unsubscribe(self._on_breakpoints_updated)
        self.instance.cfb.am_unsubscribe(self._on_cfb_event)

    def closeEvent(self, event) -> None:
        self._unregister_events()
        super().closeEvent(event)

    #
    # Private methods
    #

    def _display_function(self, the_func, send_event=True) -> None:
        if the_func is not None:
            self.set_synchronized_cursor_address(the_func.addr)

        self.function.am_obj = the_func
        if send_event:
            self.function.am_event()

        # set status bar
        self._statusbar.function = the_func

        # variable recovery
        variable_manager = self.instance.project.kb.variables
        self.variable_manager = variable_manager
        self.infodock.variable_manager = variable_manager

        # clear existing selected instructions and operands
        self.infodock.clear_selection()

        if self._flow_graph.function_graph is None or self._flow_graph.function_graph.function is not the_func:
            self._flow_graph.function_graph = (
                None
                if the_func is None
                else FunctionGraph(
                    function=the_func,
                    exception_edges=self.show_exception_edges,
                )
            )
        elif self._current_view is self._flow_graph and the_func is not None:
            self._flow_graph.show_instruction(the_func.addr)

        if self._current_view is self._linear_viewer and the_func is not None:
            self._linear_viewer.navigate_to_addr(the_func.addr)

        console_view = self.workspace.view_manager.first_view_in_category("console")
        if console_view is not None:
            console_view.set_current_function(the_func)

    def _jump_to(self, addr: int, use_animation: bool = False, is_real_addr: bool = False) -> bool:
        if self._prefer_graph and self._current_view is self._linear_viewer:
            self.display_disasm_graph(prefer=False)

        # real_addr is the address in RAM regardless of the ARM/THUMB mode
        # code_addr is an address that guarantees to hit the correct instruction
        real_addr = addr
        code_addr = addr
        is_arm = is_arm_arch(self.instance.project.arch) if not self.instance.project.am_none else False
        if is_arm and is_real_addr and code_addr & 1 == 0:
            code_addr = addr + 1  # ensures we always hit the middle of an instruction regardless of ARM/THUMB

        if self._current_view is not self._linear_viewer:
            function = locate_function(self.instance, code_addr)
            if function is not None:
                self._display_function(function)
                instr_addr = function.addr_to_instruction_addr(code_addr)
                if instr_addr is None:
                    instr_addr = code_addr
                self.infodock.select_instruction(instr_addr, unique=True, use_animation=use_animation)
                return True

            # it does not belong to any function - we need to switch to linear view mode
            self.display_linear_viewer(prefer=False)

        try:
            _, item = self.instance.cfb.floor_item(code_addr)
            if (
                code_addr != real_addr
                and isinstance(item, MemoryData)
                and (code_addr < item.addr or code_addr >= item.addr + item.size)
            ):
                # expect code but found memory data - try the real address instead
                _, item = self.instance.cfb.floor_item(real_addr)

            if isinstance(item, MemoryData) and addr < (item.addr + item.size):
                self.infodock.select_label(item.addr)
            elif isinstance(item, Block) and item.size and code_addr < (item.addr + item.size):
                addr = max(a for a in item.instruction_addrs if a <= code_addr)
                self.infodock.select_instruction(addr, unique=True, use_animation=use_animation)
                return True  # select_instruction will navigate
        except KeyError:
            pass

        self._linear_viewer.navigate_to_addr(addr)
        return True

    #
    # Utils
    #

    def _address_in_selection(self) -> tuple[str, int] | None:
        if self._insn_addr_on_context_menu is not None:
            return "insn", self._insn_addr_on_context_menu
        if len(self.infodock.selected_operands) == 1:
            selected_operand: OperandDescriptor = next(iter(self.infodock.selected_operands.values()))
            if selected_operand.num_value is not None:
                return "operand", selected_operand.num_value
        if len(self.infodock.selected_insns) == 1:
            return "insn", next(iter(self.infodock.selected_insns))
        if len(self.infodock.selected_labels) == 1:
            return "insn", next(iter(self.infodock.selected_labels))
        if (
            isinstance(self.infodock.selected_block_tree_node.am_obj, tuple)
            and len(self.infodock.selected_block_tree_node.am_obj) == 2
        ):
            ty, addr = self.infodock.selected_block_tree_node.am_obj
            if ty == "func_name":
                return ty, addr
        return None

    def _instruction_address_in_selection(self) -> int | None:
        if self._insn_addr_on_context_menu is not None:
            return self._insn_addr_on_context_menu
        if len(self.infodock.selected_insns) == 1:
            return next(iter(self.infodock.selected_insns))
        if len(self.infodock.selected_labels) == 1:
            return next(iter(self.infodock.selected_labels))
        return None

    def _get_instruction_size(self, addr: int) -> int | None:
        kb = self.instance.project.kb
        f = kb.functions.floor_func(addr)
        if f is None:
            return None
        return f.instruction_size(addr)

    @property
    def flow_graph(self):
        return self._flow_graph

    @property
    def linear_viewer(self):
        return self._linear_viewer
