from functools import partial
from typing import Callable

from angrmanagement.config import Conf

from .menu import Menu, MenuEntry, MenuSeparator


class DisasmLabelContextMenu(Menu):
    def __init__(self, disasm_view):
        super().__init__("", parent=disasm_view)

        self.addr: int = None

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

    @property
    def _disasm_view(self):
        return self.parent

    def _popup_newstate_dialog(self):
        self._disasm_view.popup_newstate_dialog(async_=True)

    def _popup_dependson_dialog(self):
        self._disasm_view.popup_dependson_dialog(addr=self.addr, func=True)

    def _toggle_label_selection(self):
        self._disasm_view.infodock.toggle_label_selection(self.addr)

    def _avoid_in_execution(self):
        self._disasm_view.avoid_addr_in_exec(self.addr)

    def _find_in_execution(self):
        self._disasm_view.find_addr_in_exec(self.addr)

    def _popup_xrefs(self):
        if self._disasm_view is None or self._disasm_view._flow_graph is None:
            return
        self._disasm_view.popup_xref_dialog(addr=self.addr, variable=None, dst_addr=self.addr, async_=True)

    #
    # Public Methods
    #

    def add_menu_entry(self, text, callback: Callable[["DisasmLabelContextMenu"], None], add_separator_first=True):
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
