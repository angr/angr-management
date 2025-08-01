from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QAction, QKeySequence

from angrmanagement.ui.icons import icon

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class HelpMenu(Menu):
    """
    Main 'Help' menu
    """

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&Help", parent=main_window)

        self.entries.extend(
            [
                MenuEntry(
                    "&Documentation", main_window.open_doc_link, shortcut=QKeySequence("Alt+H"), icon=icon("docs")
                ),
                MenuSeparator(),
                MenuEntry(
                    "&About angr-management",
                    main_window.open_about_dialog,
                    role=QAction.MenuRole.AboutRole,
                    icon=icon("about"),
                ),
            ]
        )
