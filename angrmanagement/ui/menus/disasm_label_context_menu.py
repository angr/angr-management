from __future__ import annotations

from angrmanagement.config import Conf

from .menu import Menu, MenuEntry, MenuSeparator


class DisasmLabelContextMenu(Menu):
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
    def _disasm_view(self):
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
        if self._disasm_view is None or self._disasm_view._flow_graph is None:
            return
        self._disasm_view.popup_xref_dialog(addr=self.addr, variable=None, dst_addr=self.addr)

    def _resume_cfg_from_here(self) -> None:
        self._disasm_view.resume_cfg_from(self.addr)

    def _resume_cfg_full(self) -> None:
        self._disasm_view.resume_cfg_full()
