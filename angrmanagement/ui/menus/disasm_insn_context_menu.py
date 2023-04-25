from functools import partial
from typing import TYPE_CHECKING, Callable

from angrmanagement.config import Conf

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.views.disassembly_view import DisassemblyView


class DisasmInsnContextMenu(Menu):
    """
    Dissembly Instruction's Context Menu Items and callback funcion.
    It provides context menu for dissembly instructions in the Dissembly View.
    For adding items in plugins, use `Workspace.add_disasm_insn_ctx_menu_entry`
    and `Workspace.remove_disasm_insn_ctx_menu_entry`.
    """

    def __init__(self, disasm_view: "DisassemblyView"):
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
                MenuEntry("E&xecute symbolically...", self._popup_newstate_dialog),
                MenuEntry("&Avoid in execution", self._avoid_in_execution),
                MenuEntry("&Find in execution", self._find_in_execution),
                MenuEntry("Add &hook...", self._add_hook),
                MenuEntry("View function &documentation...", self._view_docs),
                MenuEntry("Toggle &breakpoint", self._toggle_breakpoint),
                MenuEntry("&Patch...", self._popup_patch_dialog),
            ]
        )

    @property
    def _disasm_view(self) -> "DisassemblyView":
        return self.parent

    def _popup_newstate_dialog(self):
        self._disasm_view.popup_newstate_dialog(async_=True)

    def _popup_dependson_dialog(self):
        self._disasm_view.popup_dependson_dialog(use_operand=True)

    def _toggle_instruction_selection(self):
        self._disasm_view.infodock.toggle_instruction_selection(self.insn_addr)

    def _avoid_in_execution(self):
        self._disasm_view.avoid_addr_in_exec(self.insn_addr)
        self._disasm_view.refresh()

    def _find_in_execution(self):
        self._disasm_view.find_addr_in_exec(self.insn_addr)
        self._disasm_view.refresh()

    def _toggle_breakpoint(self):
        self._disasm_view.instance.breakpoint_mgr.toggle_exec_breakpoint(self.insn_addr)
        self._disasm_view.refresh()

    def _add_hook(self):
        self._disasm_view.popup_hook_dialog(async_=True)

    def _view_docs(self):
        if self._disasm_view is None:
            return
        addr = self._disasm_view._address_in_selection()
        if addr is not None:
            self._disasm_view.popup_func_doc_dialog(addr)

    def _popup_xrefs(self):
        if self._disasm_view is None or self._disasm_view._flow_graph is None:
            return
        r = self._disasm_view._flow_graph.get_selected_operand_info()
        if r is not None:
            _, ins_addr, operand = r
            self._disasm_view.parse_operand_and_popup_xref_dialog(ins_addr, operand, async_=True)

    def _popup_patch_dialog(self):
        self._disasm_view.popup_patch_dialog()

    #
    # Public Methods
    #

    def add_menu_entry(self, text, callback: Callable[["DisasmInsnContextMenu"], None], add_separator_first=True):
        if add_separator_first:
            self.entries.append(MenuSeparator())
        self.entries.append(MenuEntry(text, partial(callback, self)))

    def remove_menu_entry(self, text, remove_preceding_separator=True):
        for idx, m in enumerate(self.entries):
            if not isinstance(m, MenuEntry):
                continue
            if m.caption == text:
                self.entries.remove(m)
                if remove_preceding_separator:
                    self.entries.pop(idx - 1)
