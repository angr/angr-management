from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.logic import GlobalInfo
from angrmanagement.present import shell

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class RecentMenuEntry(shell.RecentMenuEntry):
    """
    Represents an entry in the "Load recent" list. Holds a path and an indication of what's at that path.
    """

    def __init__(self, path) -> None:
        super().__init__(path, lambda _path: self.action_target())

    def action_target(self) -> None:
        GlobalInfo.main_window.load_file(self.path)


class FileMenu(shell.FileMenu):
    """
    Lays out the entries under the 'File' menu, from :func:`~angrmanagement.present.shell.build_file_menu`. The
    entries that need a project follow the main instance's project.
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__(parent=main_window)
        shell.build_file_menu(main_window, menu=self)
        self._project = main_window.workspace.main_instance.project
        self._close_entry = self.project_entries[0]
        self._save_entries = self.project_entries[1:]
        self._project_entries = self.project_entries
        self._edit_save()
        self._project.am_subscribe(self._edit_save)

    def _edit_save(self, **_) -> None:
        self.set_project_loaded(not self._project.am_none)

    def add_recent(self, path: str) -> None:
        for entry in list(self.recent_menu.entries):
            if entry.path == path:
                self.recent_menu.remove(entry)
        self.recent_menu.add(RecentMenuEntry(path), 0)
