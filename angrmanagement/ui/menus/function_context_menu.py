"""
The function table's context menu as a Qt menu.

Deprecated: the entries now come from :func:`angrmanagement.present.functions.function_context_menu`, which the
function table uses directly. This class is kept so that code importing it keeps working.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.data.annotations import CommentKind
from angrmanagement.present.functions import function_context_menu
from angrmanagement.ui.dialogs.set_comment import SetComment

from .menu import Menu

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.ui.workspace import Workspace


class FunctionContextMenu(Menu):
    """The context menu of the functions given to :meth:`set`."""

    def __init__(self, workspace: Workspace, parent) -> None:
        super().__init__("Function", parent=parent)
        self.workspace = workspace
        self.funcs = []

    def set(self, funcs):
        self.funcs = funcs
        return self

    def _edit_function_comment(self, func: Function) -> None:
        self.workspace.main_instance.annotations.set_kind(func.addr, CommentKind.FUNCTION)
        SetComment(self.workspace, func.addr, parent=self.parent).exec_()

    def qmenu(self, extra_entries=None, cached: bool = False):
        menu = function_context_menu(self.workspace, self.funcs, edit_comment=self._edit_function_comment)
        self.entries = list(menu.entries) if menu is not None else []
        return super().qmenu(extra_entries=extra_entries, cached=cached)
