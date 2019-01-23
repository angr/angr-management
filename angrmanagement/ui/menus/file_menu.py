
from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class FileMenu(Menu):
    def __init__(self, main_window):
        super(FileMenu, self).__init__("&File", parent=main_window)

        self.entries.extend([
            MenuEntry('L&oad a new binary...', main_window.load_binary, shortcut=QKeySequence(Qt.CTRL + Qt.Key_O)),
            MenuEntry('&Save angr database...', main_window.save_database, shortcut=QKeySequence(Qt.CTRL + Qt.Key_S)),
            MenuEntry('S&ave angr database as...', main_window.save_database_as, shortcut=QKeySequence("Ctrl+Shift+S")),
            MenuSeparator(),
            MenuEntry('E&xit', main_window.quit),
        ])
