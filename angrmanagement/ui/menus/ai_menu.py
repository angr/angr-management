from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.present.shell import build_ai_menu

from .menu import Menu

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class AIMenu(Menu):
    """
    The menu for AI-assisted features; its entries are those of :func:`~angrmanagement.present.shell.build_ai_menu`.
    """

    def __init__(self, main_window: MainWindow) -> None:
        built = build_ai_menu(main_window)
        super().__init__(built.caption, built.entries, parent=main_window)
