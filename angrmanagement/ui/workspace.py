"""
The workspace of the Qt frontend.

Everything that does not need Qt is in :class:`angrmanagement.logic.workspace.BaseWorkspace`; :class:`Workspace` adds
the Qt view manager, the default views and their docking, and the Qt view commands.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6QtAds import SideBarBottom

from angrmanagement.config import Conf
from angrmanagement.data.instance import Instance
from angrmanagement.logic.workspace import BaseWorkspace

from .view_manager import ViewManager
from .views import (
    BaseView,
    CodeView,
    CommentsView,
    ConsoleView,
    DependencyView,
    DisassemblyView,
    FunctionsView,
    HexView,
    JobsView,
    LogView,
    MCPHistoryView,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.ui.main_window import MainWindow

__all__ = ["BaseView", "Instance", "Workspace"]


class Workspace(BaseWorkspace):
    """
    This class implements the angr management workspace.
    """

    view_manager: ViewManager  # pyright: ignore[reportIncompatibleVariableOverride]
    VIEW_MANAGER_CLASS = ViewManager

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__(main_window)
        self.main_window: MainWindow = main_window

        self.default_tabs = [
            DisassemblyView(self, "center", self._main_instance),
            HexView(self, "center", self._main_instance),
            CodeView(self, "center", self._main_instance),
            FunctionsView(self, "left", self._main_instance),
        ]
        if Conf.has_operation_mango:
            self.default_tabs.append(DependencyView(self, "center", self._main_instance))
        minimized_tabs = [
            ConsoleView(self, "bottom", self._main_instance),
            LogView(self, "bottom", self._main_instance),
            JobsView(self, "bottom", self.main_instance),
            MCPHistoryView(self, "bottom", self._main_instance),
            CommentsView(self, "bottom", self._main_instance),
        ]
        self.default_tabs += minimized_tabs

        enabled_tabs = [x.strip() for x in Conf.enabled_tabs.split(",") if x.strip()]
        for tab in self.default_tabs:
            if tab.__class__.__name__ in enabled_tabs or len(enabled_tabs) == 0:
                self.add_view(tab)

        for view in minimized_tabs:
            dock = self.view_manager.view_to_dock.get(view, None)
            if dock is not None:
                dock.setAutoHide(True, SideBarBottom)

        self.on_debugger_state_updated()

        DisassemblyView.register_commands(self)
        CodeView.register_commands(self)
        HexView.register_commands(self)

    @property
    def _main_window(self) -> MainWindow:
        return self.main_window

    @property
    def interactive(self) -> bool:
        """The analysis options dialog is shown only when the main window was shown at start."""
        return bool(self.main_window.shown_at_start)

    def _pick_binary(self, then: Callable[[str | None], None]) -> None:
        then(self.main_window.open_mainfile_dialog() or None)
