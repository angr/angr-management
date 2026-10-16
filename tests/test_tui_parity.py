"""
The terminal frontend offers what the Qt main window offers: the same menus, with the same captions and
shortcuts, and the same palette commands.
"""

# pylint: disable=protected-access

from __future__ import annotations

import unittest
from typing import Any

from common import AngrManagementTestCase

from angrmanagement.config import Conf
from angrmanagement.present.menus import Menu, MenuEntry, MenuSeparator
from angrmanagement.present.shell import basic_command_table, build_main_menus
from angrmanagement.ui.menus.view_menu import ToolbarMenu


def shape(menu: Menu) -> list[Any]:
    """The captions and shortcuts of a menu, its submenus nested, separators as "-"."""
    out: list[Any] = []
    for item in menu.items():
        if isinstance(item, ToolbarMenu):
            # the Qt toolbars; the terminal has none
            continue
        if isinstance(item, Menu):
            out.append((item.caption, shape(item)))
        elif isinstance(item, MenuEntry):
            shortcut = item.shortcut if item.shortcut is None or isinstance(item.shortcut, str) else "?"
            out.append((item.caption, shortcut))
        elif isinstance(item, MenuSeparator):
            out.append("-")
    # separators that bracketed a dropped submenu collapse
    collapsed: list[Any] = []
    for entry in out:
        if entry == "-" and collapsed and collapsed[-1] == "-":
            continue
        collapsed.append(entry)
    return collapsed


class TestMenuParity(AngrManagementTestCase):
    """The neutral menu bar the terminal shows is the Qt menu bar."""

    def test_same_menus(self):
        qt_menus = [
            self.main._file_menu,
            self.main._view_menu,
            self.main._analyze_menu,
            self.main._ai_menu,
            self.main._plugin_menu,
            self.main._help_menu,
        ]
        # the Qt "Load recent" submenu was built from this same list when the window was made
        neutral = build_main_menus(self.main, recent_files=Conf.recent_files)
        assert [m.caption for m in neutral] == [m.caption for m in qt_menus]
        for qt_menu, menu in zip(qt_menus, neutral, strict=True):
            assert shape(menu) == shape(qt_menu), qt_menu.caption

    def test_same_commands(self):
        captions = sorted(cmd.caption for cmd in self.main.workspace.command_manager.get_commands())
        for caption, _ in basic_command_table(self.main):
            assert caption in captions, caption


if __name__ == "__main__":
    unittest.main()
