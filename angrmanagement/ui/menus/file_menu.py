from __future__ import annotations

import platform
from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QKeySequence

from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.icons import icon

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class RecentMenuEntry(MenuEntry):
    """
    Represents an entry in the "Load recent" list. Holds a path and an indication of what's at that path.
    """

    def __init__(self, path) -> None:
        self.path = path
        super().__init__(path, self.action_target, icon=icon("file"))

    def action_target(self) -> None:
        GlobalInfo.main_window.load_file(self.path)


class FileMenu(Menu):
    """
    Lays out the entries under the 'File' menu
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&File", parent=main_window)
        self._project = main_window.workspace.main_instance.project

        self._save_entries = [
            MenuEntry(
                "&Save angr database...",
                main_window.save_database,
                shortcut=QKeySequence("Ctrl+S"),
                icon=icon("file-save"),
            ),
            MenuEntry(
                "S&ave angr database as...",
                main_window.save_database_as,
                shortcut=QKeySequence("Ctrl+Shift+S"),
                icon=icon("file-save"),
            ),
            MenuEntry("Save patched binary as...", main_window.save_patched_binary_as),
        ]
        self._edit_save()
        self._project.am_subscribe(self._edit_save)

        self.recent_menu = Menu("Load recent")
        self.entries.extend(
            [
                MenuEntry(
                    "L&oad a new binary...",
                    main_window.open_file_button,
                    shortcut=QKeySequence("Ctrl+O"),
                    icon=icon("file-open"),
                ),
                MenuEntry(
                    "Load a &trace file...",
                    main_window.open_trace_file_button,
                    shortcut=QKeySequence("Ctrl+Shift+T"),
                ),
                self.recent_menu,
                MenuSeparator(),
                MenuEntry(
                    "&Load angr database...",
                    main_window.load_database,
                    shortcut=QKeySequence("Ctrl+L"),
                    icon=icon("file-open"),
                ),
                *self._save_entries,
                MenuSeparator(),
                MenuEntry("Load a new &trace...", main_window.load_trace),
                MenuSeparator(),
                MenuEntry(
                    "&Preferences...",
                    main_window.preferences,
                    shortcut=QKeySequence("Ctrl+Comma"),
                    role=QAction.MenuRole.PreferencesRole,
                    icon=icon("preferences") if platform.system() != "Darwin" else None,
                ),
                MenuSeparator(),
                MenuEntry("E&xit", main_window.quit),
            ]
        )

    def _edit_save(self, **_) -> None:
        enable: bool = not self._project.am_none
        for i in self._save_entries:
            (i.enable if enable else i.disable)()

    def add_recent(self, path: str) -> None:
        for entry in list(self.recent_menu.entries):
            if entry.path == path:
                self.recent_menu.remove(entry)
        self.recent_menu.add(RecentMenuEntry(path), 0)
