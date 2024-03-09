from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence

from angrmanagement.ui.icons import icon

from .menu import Menu, MenuEntry, MenuSeparator


class AnalyzeMenu(Menu):
    def __init__(self, main_window):
        super().__init__("&Analyze", parent=main_window)
        self.entries.extend(
            [
                MenuEntry(
                    "&Run Analysis...",
                    main_window.run_analysis,
                    shortcut=QKeySequence(Qt.Key_F4),
                    icon=icon("run-analysis"),
                ),
                MenuSeparator(),
                MenuEntry(
                    "&Decompile",
                    main_window.decompile_current_function,
                    shortcut=QKeySequence(Qt.Key_F5),
                    icon=icon("pseudocode-view"),
                ),
                MenuEntry(
                    "View in Proximity &Browser",
                    main_window.view_proximity_for_current_function,
                    shortcut=QKeySequence("Ctrl+B"),
                ),
                MenuEntry("&Interact", main_window.interact, shortcut=QKeySequence(Qt.Key_F6)),
            ],
        )
