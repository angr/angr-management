import os

from PySide6.QtWidgets import QFileDialog

from angrmanagement.plugins import BasePlugin


class SourceImporterPlugin(BasePlugin):
    """
    A plugin that adds scraping source code from the local filesystem and displaying it as an alternative to the
    pseudocode.
    """

    DISPLAY_NAME = "Source Importer"

    def __init__(self, workspace):
        super().__init__(workspace)

        self.source_paths = []
        self._import_from_project()

    def handle_project_initialization(self):
        self._import_from_project()

    def _import_from_project(self):
        self.source_paths = []
        if self.workspace.main_instance.original_binary_path:
            self.source_paths.append(os.path.dirname(self.workspace.main_instance.original_binary_path))

    def decompile_callback(self, func):
        for source_root in self.source_paths:
            self.workspace.main_instance.project.analyses.ImportSourceCode(
                func, flavor="source", source_root=source_root
            )

    MENU_BUTTONS = ["Import source path"]

    def handle_click_menu(self, idx):
        if idx != 0:
            return
        result = QFileDialog.getExistingDirectory(
            self.workspace.main_window,
            "Select source root",
            ".",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks,
        )
        if result is not None:
            self.source_paths.append(result)
