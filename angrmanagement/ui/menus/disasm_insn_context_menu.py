
from functools import partial
from typing import Callable

from .menu import Menu, MenuEntry, MenuSeparator

class DisasmInsnContextMenu(Menu):
    def __init__(self, disasm_view):
        super(DisasmInsnContextMenu, self).__init__("", parent=disasm_view)

        self.insn_addr = None

        self.entries.extend([
            MenuEntry('T&oggle selection', self._toggle_instruction_selection),
            MenuSeparator(),
            MenuEntry('&XRefs...', self._popup_xrefs),
            MenuSeparator(),
            MenuEntry('E&xecute symbolically...', self._popup_newstate_dialog),
            MenuEntry('&Avoid in execution...', self._avoid_in_execution)
        ])

    @property
    def _disasm_view(self):
        return self.parent

    def _popup_newstate_dialog(self): self._disasm_view.popup_newstate_dialog(async_=True)

    def _toggle_instruction_selection(self): self._disasm_view.infodock.toggle_instruction_selection(self.insn_addr)

    def _avoid_in_execution(self): self._disasm_view.avoid_addr_in_exec(self.insn_addr)

    def _popup_xrefs(self):
        if self._disasm_view is None or self._disasm_view._flow_graph is None:
            return
        r = self._disasm_view._flow_graph.get_selected_operand_info()
        if r is not None:
            _, ins_addr, operand = r
            self._disasm_view.parse_operand_and_popup_xref_dialog(ins_addr, operand, async_=True)

    #
    # Public Methods
    #

    def add_menu_entry(self, text, callback: Callable[['DisasmInsnContextMenu'], None], add_separator_first=True):
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
                    self.entries.pop(idx-1)
