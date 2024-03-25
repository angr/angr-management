from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.logic import GlobalInfo

from .menu import Menu, MenuEntry

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class FunctionContextMenu(Menu):
    def __init__(self, workspace: Workspace, parent) -> None:
        super().__init__("Function", parent=parent)
        self.workspace = workspace

        self.funcs = []

        # TODO add Rename, Change Type, xrefs, etc

    def set(self, funcs):
        self.funcs = funcs
        return self

    def qmenu(self, extra_entries=None):
        self.entries = []
        if len(self.funcs):
            self.entries.append(
                MenuEntry("Show Function Info", lambda: self.workspace.show_function_info(self.funcs[0]))
            )
        if extra_entries is None:
            extra_entries = ()
        return super().qmenu(
            extra_entries=list(GlobalInfo.main_window.workspace.plugins.build_context_menu_functions(self.funcs))
            + list(extra_entries),
            cached=False,
        )
