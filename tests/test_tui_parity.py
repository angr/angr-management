"""
The terminal frontend offers what the Qt main window offers: the same menus, with the same captions and
shortcuts, and the same palette commands.
"""

# pylint: disable=protected-access

from __future__ import annotations

import unittest
from typing import Any

from common import AngrManagementTestCase

from angrmanagement.logic import GlobalInfo
from angrmanagement.present.menus import Menu, MenuEntry, MenuSeparator
from angrmanagement.present.shell import basic_command_table
from angrmanagement.tui.app import AmApp
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
    return collapse(out)


def collapse(shown: list[Any]) -> list[Any]:
    """``shown`` with each run of separators made one, as separators that bracketed a dropped entry become."""
    collapsed: list[Any] = []
    for entry in shown:
        if entry == "-" and collapsed and collapsed[-1] == "-":
            continue
        collapsed.append(entry)
    return collapsed


#: what the terminal's menus have and the Qt ones do not, as (menu, entry): the Qt Toolbars submenu stands there
TERMINAL_ONLY = {("&View", ("&Bottom Area", "F12"))}


class TestMenuParity(AngrManagementTestCase):
    """The menu bar of the terminal frontend is the Qt menu bar."""

    def test_same_menus(self):
        qt_menus = [
            self.main._file_menu,
            self.main._view_menu,
            self.main._analyze_menu,
            self.main._ai_menu,
            self.main._plugin_menu,
            self.main._help_menu,
        ]
        # the terminal app's own menus, built as it starts; it is not run, only made and shut down
        app = AmApp(interactive=False)
        try:
            terminal = list(app.menus)
        finally:
            app.shutdown()
        assert GlobalInfo.main_window is self.main
        assert [m.caption for m in terminal] == [m.caption for m in qt_menus]
        for qt_menu, menu in zip(qt_menus, terminal, strict=True):
            extra = [entry for caption, entry in TERMINAL_ONLY if caption == menu.caption]
            got = shape(menu)
            assert all(entry in got for entry in extra), (menu.caption, extra)
            assert shape(qt_menu) == collapse([entry for entry in got if entry not in extra]), qt_menu.caption

    def test_same_commands(self):
        captions = sorted(cmd.caption for cmd in self.main.workspace.command_manager.get_commands())
        for caption, _ in basic_command_table(self.main):
            assert caption in captions, caption


if __name__ == "__main__":
    unittest.main()
