"""
The context menus of the disassembly view, as data.

Each menu takes the object whose methods its entries call: the Qt ``DisassemblyView``, which forwards what is not Qt to
its presenter, or the :class:`~angrmanagement.present.disasm.DisasmPresenter` itself, which the terminal frontend
uses. ``angrmanagement.ui.menus.disasm_*`` re-export these classes.
"""

from __future__ import annotations

from typing import Any

from angrmanagement.config import Conf

from .menus import Menu, MenuEntry, MenuSeparator


class DisasmInsnContextMenu(Menu):
    """
    Dissembly Instruction's Context Menu Items and callback funcion.
    It provides context menu for dissembly instructions in the Dissembly View.
    For adding items in plugins, use `Workspace.add_disasm_insn_ctx_menu_entry`
    and `Workspace.remove_disasm_insn_ctx_menu_entry`.
    """

    insn_addr: int | None

    def __init__(self, disasm_view: Any) -> None:
        super().__init__("", parent=disasm_view)

        self.insn_addr = None

        self.entries.extend(
            [
                MenuEntry("T&oggle selection", self._toggle_instruction_selection),
                MenuSeparator(),
                MenuEntry("&XRefs...", self._popup_xrefs),
                MenuSeparator(),
            ]
        )
        if Conf.has_operation_mango:
            self.entries.extend(
                [
                    MenuEntry("&Depends on...", self._popup_dependson_dialog),
                    MenuSeparator(),
                ]
            )
        self.entries.extend(
            [
                MenuEntry("&Comment", self._begin_inline_comment),
                MenuEntry("Comment (&multi-line)...", self._popup_comment_dialog),
                MenuEntry("Set &function comment", self._set_function_comment),
                MenuEntry("Toggle &repeatable comment", self._toggle_repeatable_comment),
                MenuEntry("Toggle book&mark", self._toggle_bookmark),
                MenuSeparator(),
                MenuEntry("E&xecute symbolically...", self._popup_newstate_dialog),
                MenuEntry("&Avoid in execution", self._avoid_in_execution),
                MenuEntry("&Find in execution", self._find_in_execution),
                MenuEntry("Add &hook...", self._add_hook),
                MenuEntry("View function &documentation...", self._view_docs),
                MenuEntry("Toggle &breakpoint", self._toggle_breakpoint),
                MenuEntry("&Patch...", self._popup_patch_dialog),
            ]
        )
        self.resume_cfg_here_entry = MenuEntry("Resume CFG recovery from &here", self._resume_cfg_from_here)
        self.resume_cfg_full_entry = MenuEntry("Resume f&ull CFG recovery", self._resume_cfg_full)
        self.entries.extend(
            [
                MenuSeparator(),
                self.resume_cfg_here_entry,
                self.resume_cfg_full_entry,
            ]
        )

    @property
    def _disasm_view(self) -> Any:
        return self.parent

    def _popup_newstate_dialog(self) -> None:
        self._disasm_view.popup_newstate_dialog()

    def _popup_dependson_dialog(self) -> None:
        self._disasm_view.popup_dependson_dialog(use_operand=True)

    def _toggle_instruction_selection(self) -> None:
        self._disasm_view.infodock.toggle_instruction_selection(self.insn_addr)

    def _avoid_in_execution(self) -> None:
        self._disasm_view.avoid_addr_in_exec(self.insn_addr)
        self._disasm_view.refresh()

    def _find_in_execution(self) -> None:
        self._disasm_view.find_addr_in_exec(self.insn_addr)
        self._disasm_view.refresh()

    def _toggle_breakpoint(self) -> None:
        self._disasm_view.instance.breakpoint_mgr.toggle_exec_breakpoint(self.insn_addr)
        self._disasm_view.refresh()

    def _add_hook(self) -> None:
        self._disasm_view.popup_hook_dialog()

    def _begin_inline_comment(self) -> None:
        self._disasm_view.begin_inline_comment(self.insn_addr)

    def _popup_comment_dialog(self) -> None:
        self._disasm_view.popup_comment_dialog()

    def _set_function_comment(self) -> None:
        self._disasm_view.set_function_comment(self.insn_addr)

    def _toggle_repeatable_comment(self) -> None:
        self._disasm_view.toggle_repeatable_comment(self.insn_addr)

    def _toggle_bookmark(self) -> None:
        self._disasm_view.workspace.toggle_bookmark(self.insn_addr)

    def _view_docs(self) -> None:
        if self._disasm_view is None:
            return
        addr = self._disasm_view.address_in_selection()
        if addr is not None:
            self._disasm_view.popup_func_doc_dialog(addr)

    def _popup_xrefs(self) -> None:
        if self._disasm_view is None or getattr(self._disasm_view, "flow_graph", None) is None:
            return
        r = self._disasm_view.get_selected_operand_info()
        if r is not None:
            _, ins_addr, operand = r
            self._disasm_view.parse_operand_and_popup_xref_dialog(ins_addr, operand)

    def _popup_patch_dialog(self) -> None:
        self._disasm_view.popup_patch_dialog()

    def _resume_cfg_from_here(self) -> None:
        if self.insn_addr is not None:
            self._disasm_view.resume_cfg_from(self.insn_addr)

    def _resume_cfg_full(self) -> None:
        self._disasm_view.resume_cfg_full()


class DisasmLabelContextMenu(Menu):
    """
    The context menu of a label in the disassembly view.
    """

    addr: int | None

    def __init__(self, disasm_view) -> None:
        super().__init__("", parent=disasm_view)

        self.addr = None

        self.entries.extend(
            [
                MenuEntry("T&oggle selection", self._toggle_label_selection),
                MenuSeparator(),
                MenuEntry("&XRefs...", self._popup_xrefs),
                MenuSeparator(),
            ]
        )
        if Conf.has_operation_mango:
            self.entries.extend(
                [
                    MenuEntry("&Depends on...", self._popup_dependson_dialog),
                    MenuSeparator(),
                ]
            )
        self.entries.extend(
            [
                MenuEntry("E&xecute symbolically...", self._popup_newstate_dialog),
                MenuEntry("&Avoid in execution...", self._avoid_in_execution),
                MenuEntry("&Find in execution...", self._find_in_execution),
            ]
        )
        self.resume_cfg_here_entry = MenuEntry("Resume CFG recovery from &here", self._resume_cfg_from_here)
        self.resume_cfg_full_entry = MenuEntry("Resume f&ull CFG recovery", self._resume_cfg_full)
        self.entries.extend(
            [
                MenuSeparator(),
                self.resume_cfg_here_entry,
                self.resume_cfg_full_entry,
            ]
        )

    @property
    def _disasm_view(self) -> Any:
        return self.parent

    def _popup_newstate_dialog(self) -> None:
        self._disasm_view.popup_newstate_dialog()

    def _popup_dependson_dialog(self) -> None:
        self._disasm_view.popup_dependson_dialog(addr=self.addr, func=True)

    def _toggle_label_selection(self) -> None:
        self._disasm_view.infodock.toggle_label_selection(self.addr)

    def _avoid_in_execution(self) -> None:
        self._disasm_view.avoid_addr_in_exec(self.addr)

    def _find_in_execution(self) -> None:
        self._disasm_view.find_addr_in_exec(self.addr)

    def _popup_xrefs(self) -> None:
        if self._disasm_view is None or getattr(self._disasm_view, "flow_graph", None) is None:
            return
        self._disasm_view.popup_xref_dialog(addr=self.addr, variable=None, dst_addr=self.addr)

    def _resume_cfg_from_here(self) -> None:
        view = self._disasm_view
        if view is not None and self.addr is not None:
            view.resume_cfg_from(self.addr)

    def _resume_cfg_full(self) -> None:
        view = self._disasm_view
        if view is not None:
            view.resume_cfg_full()


class DisasmUnknownContextMenu(Menu):
    """
    Context menu for undefined bytes in the linear disassembly view. Its main purpose is to let the user resume a
    cancelled CFG recovery from a byte offset that has not been analyzed yet.
    """

    addr: int | None

    def __init__(self, disasm_view: Any) -> None:
        super().__init__("", parent=disasm_view)

        self._view = disasm_view
        self.addr = None

        self.resume_cfg_here_entry = MenuEntry("Resume CFG recovery from &here", self._resume_cfg_from_here)
        self.resume_cfg_full_entry = MenuEntry("Resume f&ull CFG recovery", self._resume_cfg_full)
        self.entries.extend(
            [
                self.resume_cfg_here_entry,
                self.resume_cfg_full_entry,
            ]
        )

    @property
    def _disasm_view(self) -> Any:
        return self._view

    def _resume_cfg_from_here(self) -> None:
        if self.addr is not None:
            self._disasm_view.resume_cfg_from(self.addr)

    def _resume_cfg_full(self) -> None:
        self._disasm_view.resume_cfg_full()


class DisasmOptionsMenu(Menu):
    """
    The disassembly view's options: checkable display toggles.
    """

    def __init__(self, disasm_view) -> None:
        super().__init__("", parent=disasm_view)
        self._view: Any = disasm_view

        self._show_minimap_action = MenuEntry(
            "Show &minimap", self._show_minimap, checkable=True, checked=self._view.show_minimap
        )
        self._smart_highlighting_action = MenuEntry(
            "Smart &highlighting", self._smart_highlighting, checkable=True, checked=self._view.smart_highlighting
        )
        self._show_address_action = MenuEntry(
            "Show &address", self._show_address, checkable=True, checked=self._view.show_address
        )
        self._show_variable_action = MenuEntry(
            "Show &variable", self._show_variable, checkable=True, checked=self._view.show_variable
        )
        self._show_variable_ident_action = MenuEntry(
            "Show variable &identifiers",
            self._show_variable_identifier,
            checkable=True,
            checked=self._view.show_variable_identifier,
        )
        self._show_exception_edges_action = MenuEntry(
            "Show &exception transition edges",
            self._show_exception_edges,
            checkable=True,
            checked=self._view.show_exception_edges,
        )

        self.entries.extend(
            [
                self._show_minimap_action,
                self._smart_highlighting_action,
                self._show_address_action,
                self._show_variable_action,
                self._show_variable_ident_action,
                self._show_exception_edges_action,
            ]
        )

    def _show_minimap(self) -> None:
        checked = self._show_minimap_action.checked
        self._view.toggle_show_minimap(checked)

    def _smart_highlighting(self) -> None:
        checked = self._smart_highlighting_action.checked
        self._view.toggle_smart_highlighting(checked)

    def _show_address(self) -> None:
        checked = self._show_address_action.checked
        self._view.toggle_show_address(checked)

    def _show_variable(self) -> None:
        checked = self._show_variable_action.checked
        self._view.toggle_show_variable(checked)

    def _show_variable_identifier(self) -> None:
        checked = self._show_variable_ident_action.checked
        self._view.toggle_show_variable_identifier(checked)

    def _show_exception_edges(self) -> None:
        checked = self._show_exception_edges_action.checked
        self._view.toggle_show_exception_edges(checked)
