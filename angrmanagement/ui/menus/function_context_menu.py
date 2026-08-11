from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.data.annotations import CommentKind
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.dialogs.set_comment import SetComment

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

    def _edit_function_comment(self) -> None:
        if not self.funcs:
            return
        addr = self.funcs[0].addr
        self.workspace.main_instance.annotations.set_kind(addr, CommentKind.FUNCTION)
        SetComment(self.workspace, addr, parent=self.parent).exec_()

    def qmenu(self, extra_entries=None):
        self.entries = []
        if len(self.funcs):
            self.entries.append(
                MenuEntry("Show Function Info", lambda: self.workspace.show_function_info(self.funcs[0]))
            )
            self.entries.append(MenuEntry("Edit Function Comment...", self._edit_function_comment))
        if extra_entries is None:
            extra_entries = ()
        return super().qmenu(
            extra_entries=list(GlobalInfo.main_window.workspace.plugins.build_context_menu_functions(self.funcs))
            + list(extra_entries),
            cached=False,
        )
