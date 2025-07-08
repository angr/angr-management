from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.ui.icons import icon

from .toolbar import Toolbar, ToolbarAction

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class FileToolbar(Toolbar):
    def __init__(self, main_window: MainWindow) -> None:
        super().__init__(main_window, "File")

        self.actions = [
            ToolbarAction(
                icon("file-open"),
                "Open File",
                "Open a new file for analysis",
                main_window.open_file_button,
            ),
            ToolbarAction(
                icon("file-save"),
                "Save",
                "Save angr database",
                main_window.save_database,
            ),
        ]
