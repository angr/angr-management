
from PySide2.QtGui import QKeySequence
from PySide2.QtCore import Qt

from .menu import Menu, MenuEntry, MenuSeparator


class AnalyzeMenu(Menu):
    def __init__(self, main_window):
        super().__init__("&Analyze", parent=main_window)
        self.entries.extend([
            MenuEntry('&Run Analysis...', main_window.run_analysis,
                      shortcut=QKeySequence(Qt.Key_F4)),
            MenuSeparator(),
            MenuEntry('&Decompile',
                main_window.decompile_current_function,
                shortcut=QKeySequence(Qt.Key_F5)),
            MenuEntry('View in Proximity &Browser',
                      main_window.view_proximity_for_current_function,
                      shortcut=QKeySequence(Qt.CTRL + Qt.Key_B)),
            MenuEntry('&Interact',
                main_window.interact,
                shortcut=QKeySequence(Qt.Key_F6)),
        ],)
