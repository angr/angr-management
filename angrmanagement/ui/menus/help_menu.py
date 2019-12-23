
from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class HelpMenu(Menu):
    def __init__(self, main_window):
        super().__init__("&Help", parent=main_window)

        self.entries.extend([
            MenuEntry('&Documentation', main_window.open_doc_link,  shortcut=QKeySequence(Qt.ALT + Qt.Key_H)),
            MenuSeparator(),
            MenuEntry('About angr...', main_window.open_about_dialog)
        ])
