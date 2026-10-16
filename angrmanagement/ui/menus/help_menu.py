from __future__ import annotations

from typing import TYPE_CHECKING

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
                MenuEntry("&Documentation", main_window.open_doc_link, shortcut="Alt+H", icon="docs"),
                MenuSeparator(),
                MenuEntry(
                    "&About angr-management",
                    main_window.open_about_dialog,
                    role="about",
                    icon="about",
                ),
            ]
        )
