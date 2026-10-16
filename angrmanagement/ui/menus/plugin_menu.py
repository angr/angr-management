from __future__ import annotations

from typing import TYPE_CHECKING

from .menu import Menu, MenuEntry

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class PluginMenu(Menu):
    """The Plugins menu of the main window."""

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__("&Plugins", parent=main_window)

        self.entries.extend([MenuEntry("&Manage Plugins...", main_window.open_load_plugins_dialog, icon="plugins")])
