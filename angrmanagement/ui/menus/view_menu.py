from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class ViewMenu(Menu):
    def __init__(self, main_window):
        super(ViewMenu, self).__init__("&View", parent=main_window)

        self.entries.extend([
            MenuEntry('Next Tab', main_window.next_tab, shortcut=QKeySequence("Ctrl+Tab")),
            MenuEntry('Previous Tab', main_window.previous_tab, shortcut=QKeySequence("Ctrl+Shift+Tab")),
            MenuSeparator(),
            MenuEntry('Split View', main_window.workspace.split_view, shortcut=QKeySequence("Ctrl+D")),
            MenuEntry('Unsplit View', main_window.workspace.unsplit_view, shortcut=QKeySequence("Ctrl+U")),
        ])
