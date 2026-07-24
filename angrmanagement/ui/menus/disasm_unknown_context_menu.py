from __future__ import annotations

from typing import TYPE_CHECKING

from .menu import Menu, MenuEntry

if TYPE_CHECKING:
    from angrmanagement.ui.views.disassembly_view import DisassemblyView


class DisasmUnknownContextMenu(Menu):
    """
    Context menu for undefined bytes in the linear disassembly view. Its main purpose is to let the user resume a
    cancelled CFG recovery from a byte offset that has not been analyzed yet.
    """

    addr: int | None

    def __init__(self, disasm_view: DisassemblyView) -> None:
        super().__init__("", parent=disasm_view)

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
    def _disasm_view(self) -> DisassemblyView:
        return self.parent

    def _resume_cfg_from_here(self) -> None:
        self._disasm_view.resume_cfg_from(self.addr)

    def _resume_cfg_full(self) -> None:
        self._disasm_view.resume_cfg_full()
