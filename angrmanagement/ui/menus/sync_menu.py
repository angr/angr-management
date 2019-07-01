
from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry


class SyncMenu(Menu):
    def __init__(self, main_window):
        super().__init__("&Sync", parent=main_window)

        self.entries.extend([
            MenuEntry('&Configure...', main_window.setup_sync, key="config", enabled=False),
        ])
