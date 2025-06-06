from __future__ import annotations

import os
from typing import TYPE_CHECKING

from PySide6.QtGui import QIcon

from angrmanagement.consts import IMG_LOCATION
from angrmanagement.ui.icons import icon

from .toolbar import Toolbar, ToolbarAction

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow

try:
    import archr
except ImportError:
    archr = None


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
                QIcon(os.path.join(IMG_LOCATION, "toolbar-docker-open.png")),
                "Open Docker Target",
                "Open a file located within a docker image for analysis",
                main_window.open_docker_button,
            ),
            ToolbarAction(
                icon("file-save"),
                "Save",
                "Save angr database",
                main_window.save_database,
            ),
        ]

        if archr is None:
            self.actions.pop(1)
