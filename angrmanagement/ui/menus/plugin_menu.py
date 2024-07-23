from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.ui.icons import icon

from .menu import Menu, MenuEntry

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class PluginMenu(Menu):
    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&Plugins", parent=main_window)

        self.entries.extend(
            [MenuEntry("&Manage Plugins...", main_window.open_load_plugins_dialog, icon=icon("plugins"))]
        )
