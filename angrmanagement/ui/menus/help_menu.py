from PySide6.QtGui import QKeySequence

from .menu import Menu, MenuEntry, MenuSeparator


class HelpMenu(Menu):
    """
    Main 'Help' menu
    """

    def __init__(self, main_window):
        super().__init__("&Help", parent=main_window)

        self.entries.extend(
            [
                MenuEntry("&Documentation", main_window.open_doc_link, shortcut=QKeySequence("Alt+H")),
                MenuSeparator(),
                MenuEntry("About angr...", main_window.open_about_dialog),
            ]
        )
