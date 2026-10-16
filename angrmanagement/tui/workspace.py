"""The workspace of the terminal frontend."""

from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.workspace import BaseWorkspace
from angrmanagement.present.shell import register_basic_commands

from .view_manager import TuiViewManager

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from .app import AmApp

#: The default views, as the Qt workspace opens them: category, area, and the Qt class name ``enabled_tabs`` uses.
DEFAULT_VIEWS = [
    ("functions", "left", "FunctionsView"),
    ("console", "bottom", "ConsoleView"),
    ("log", "bottom", "LogView"),
    ("jobs", "bottom", "JobsView"),
    ("mcp_history", "bottom", "MCPHistoryView"),
    ("comments", "bottom", "CommentsView"),
]


class TuiWorkspace(BaseWorkspace):
    """The workspace, with views in the terminal."""

    view_manager: TuiViewManager  # pyright: ignore[reportIncompatibleVariableOverride]
    VIEW_MANAGER_CLASS = TuiViewManager

    def __init__(self, app: AmApp) -> None:
        super().__init__(app)
        self.app = app

    def register_commands(self) -> None:
        """Register the main window's palette commands; the app must have this workspace by then."""
        register_basic_commands(self.command_manager, self.app)

    def add_default_views(self) -> None:
        enabled_tabs = [x.strip() for x in Conf.enabled_tabs.split(",") if x.strip()]
        for category, position, qt_name in DEFAULT_VIEWS:
            if not enabled_tabs or qt_name in enabled_tabs:
                self.view_manager.create_view(category, position)

    @property
    def interactive(self) -> bool:
        return bool(getattr(self.app, "interactive", True))

    def _refresh_view(self, view) -> None:
        refresh_view = getattr(view, "refresh_view", None)
        if refresh_view is not None:
            refresh_view()
        else:
            view.refresh()

    def run_analysis(self, use_default_options: bool = False) -> None:
        if self.main_instance.project.am_none:
            return
        if self.main_instance.analysis_configuration is None:
            self.main_instance.analysis_configuration = self.analysis_manager.get_default_analyses_configuration()
        if not self.interactive or use_default_options:
            self.analysis_manager.run_analysis()
            return

        async def ask_then_run() -> None:
            services = GlobalInfo.ui_services
            ask = getattr(services, "ask_analysis_options", None)
            configuration = self.main_instance.analysis_configuration
            if ask is not None:
                configuration = await ask(configuration)
            if configuration is None:
                return
            self.main_instance.analysis_configuration = configuration
            self.analysis_manager.run_analysis()

        self.app.run_worker(ask_then_run(), exit_on_error=False)

    def on_function_selected(self, func: Function) -> None:
        super().on_function_selected(func)
        console = self.view_manager.first_view_in_category("console")
        if console is not None:
            console.set_current_function(func)
        if self.view_manager.first_view_in_category("disassembly") is None:
            self.app.show_status(f"{func.name} at {func.addr:#x} (func in the console)")
