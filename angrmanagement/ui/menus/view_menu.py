from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class ViewMenu(Menu):
    def __init__(self, main_window):
        super(ViewMenu, self).__init__("&View", parent=main_window)

        self.entries.extend([
            MenuEntry('Next Tab', main_window.workspace.view_manager.next_tab, shortcut=QKeySequence("Ctrl+Tab")),
            MenuEntry('Previous Tab', main_window.workspace.view_manager.previous_tab, shortcut=QKeySequence("Ctrl+Shift+Tab")),
            MenuSeparator(),
            MenuEntry('Split / Unsplit View', main_window.workspace.toggle_split, shortcut=QKeySequence("Ctrl+D")),
        ])
