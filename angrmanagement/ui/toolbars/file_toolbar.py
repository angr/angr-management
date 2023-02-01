import os

from PySide6.QtGui import QIcon

from angrmanagement.config import IMG_LOCATION

from .toolbar import Toolbar, ToolbarAction

try:
    import archr
except ImportError:
    archr = None


class FileToolbar(Toolbar):
    def __init__(self, main_window):
        super().__init__(main_window, "File")

        self.actions = [
            ToolbarAction(
                QIcon(os.path.join(IMG_LOCATION, "toolbar-file-open.ico")),
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
                QIcon(os.path.join(IMG_LOCATION, "toolbar-file-save.png")),
                "Save",
                "Save angr database",
                main_window.save_database,
            ),
        ]

        if archr is None:
            self.actions.pop(1)
