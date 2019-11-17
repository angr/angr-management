
from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class FileMenu(Menu):
    def __init__(self, main_window):
        super(FileMenu, self).__init__("&File", parent=main_window)

        self.entries.extend([
            MenuEntry('L&oad a new binary...', main_window.open_file_button, shortcut=QKeySequence(Qt.CTRL + Qt.Key_O)),
            MenuEntry('Loa&d a new docker target...', main_window.open_docker_button, shortcut=QKeySequence(Qt.CTRL + Qt.SHIFT + Qt.Key_O)),
            MenuEntry('Load a &trace...', main_window.open_trace, enabled=False, shortcut=QKeySequence(Qt.CTRL + Qt.SHIFT + Qt.Key_T), key='load_trace'),
            MenuEntry('Load a &Multi-Trace...', main_window.open_multi_trace, enabled=False,
                      shortcut=QKeySequence(Qt.CTRL + Qt.SHIFT + Qt.Key_M), key='load_multi_trace'),
            MenuEntry('&Save angr database...', main_window.save_database, shortcut=QKeySequence(Qt.CTRL + Qt.Key_S)),
            MenuEntry('S&ave angr database as...', main_window.save_database_as, shortcut=QKeySequence("Ctrl+Shift+S")),
            MenuSeparator(),
            MenuEntry('E&xit', main_window.quit),
        ])
