from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.plugins import BasePlugin

from .bhinstance import BhInstance
from .run_target_dialog import RunTargetDialog

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class BinharnessPlugin(BasePlugin):
    """BinHarness plugin for angr management."""

    MENU_BUTTONS = [
        "Binharness: Run",
    ]

    def __init__(self, workspace: Workspace):
        super().__init__(workspace)

        workspace.main_instance.register_container("binharness", BhInstance, BhInstance, "Binharness instance")

    # Internal methods

    def _bh(self) -> BhInstance:
        return self.workspace.main_instance.binharness

    def _show_run_target_dialog(self):
        run_target_dialog = RunTargetDialog(self.workspace, self._bh())
        run_target_dialog.exec_()

    # Event handlers

    def handle_project_initialization(self):
        self._bh().load_project(self.workspace.main_instance.project)

    def handle_click_menu(self, idx: int):
        # TODO: Error if no project loaded
        if idx == 0:
            self._show_run_target_dialog()
        else:
            raise NotImplementedError
