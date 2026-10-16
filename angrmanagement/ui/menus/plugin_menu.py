from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.present.shell import build_plugin_menu

from .menu import Menu

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class PluginMenu(Menu):
    """The Plugins menu of the main window, from :func:`~angrmanagement.present.shell.build_plugin_menu`."""

    def __init__(self, main_window: MainWindow) -> None:
        built = build_plugin_menu(main_window)
        super().__init__(built.caption, built.entries, parent=main_window)
