from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.present.shell import build_help_menu

from .menu import Menu

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class HelpMenu(Menu):
    """
    Main 'Help' menu, from :func:`~angrmanagement.present.shell.build_help_menu`.
    """

    def __init__(self, main_window: MainWindow) -> None:
        built = build_help_menu(main_window)
        super().__init__(built.caption, built.entries, parent=main_window)
