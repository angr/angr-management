import platform

from PySide6.QtGui import QAction, QKeySequence

from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.icons import icon

from .menu import Menu, MenuEntry, MenuSeparator

try:
    import archr
except ImportError:
    archr = None


class RecentMenuEntry(MenuEntry):
    """
    Represents an entry in the "Load recent" list. Holds a path and an indication of what's at that path.
    """

    def __init__(self, path):
        self.path = path
        super().__init__(path, self.action_target)

    def action_target(self):
        GlobalInfo.main_window.load_file(self.path)


class FileMenu(Menu):
    """
    Lays out the entries under the 'File' menu
    """

    def __init__(self, main_window):
        super().__init__("&File", parent=main_window)
        self._project = main_window.workspace.main_instance.project

        self._save_entries = [
            MenuEntry("&Save angr database...", main_window.save_database, shortcut=QKeySequence("Ctrl+S")),
            MenuEntry("S&ave angr database as...", main_window.save_database_as, shortcut=QKeySequence("Ctrl+Shift+S")),
            MenuEntry("Save patched binary as...", main_window.save_patched_binary_as),
        ]
        self._edit_save()
        self._project.am_subscribe(self._edit_save)

        self.recent_menu = Menu("Load recent")
        self.entries.extend(
            [
                MenuEntry("L&oad a new binary...", main_window.open_file_button, shortcut=QKeySequence("Ctrl+O")),
                *(
                    []
                    if archr is None
                    else [
                        MenuEntry(
                            "Loa&d a new docker target...",
                            main_window.open_docker_button,
                            shortcut=QKeySequence("Ctrl+Shift+O"),
                        ),
                    ]
                ),
                MenuEntry(
                    "Load a &trace file...",
                    main_window.open_trace_file_button,
                    shortcut=QKeySequence("Ctrl+Shift+T"),
                ),
                self.recent_menu,
                MenuSeparator(),
                MenuEntry("&Load angr database...", main_window.load_database, shortcut=QKeySequence("Ctrl+L")),
                *self._save_entries,
                MenuSeparator(),
                MenuEntry("Load a new &trace...", main_window.load_trace),
                MenuSeparator(),
                MenuEntry(
                    "&Preferences...",
                    main_window.preferences,
                    shortcut=QKeySequence("Ctrl+Comma"),
                    role=QAction.PreferencesRole,
                    icon=icon("preferences") if platform.system() != "Darwin" else None,
                ),
                MenuSeparator(),
                MenuEntry("E&xit", main_window.quit),
            ]
        )

    def _edit_save(self, **_):
        enable: bool = not self._project.am_none
        for i in self._save_entries:
            (i.enable if enable else i.disable)()

    def add_recent(self, path: str):
        for entry in list(self.recent_menu.entries):
            if entry.path == path:
                self.recent_menu.remove(entry)
        self.recent_menu.add(RecentMenuEntry(path), 0)
