"""
Test that no two always-active key bindings in the main window collide. Qt silently swallows
ambiguous shortcuts (`QAction::event: Ambiguous shortcut overload`), so a collision means both
actions stop working.
"""

from __future__ import annotations

import unittest
from collections import defaultdict

from common import AngrManagementTestCase
from PySide6.QtCore import Qt
from PySide6.QtGui import QShortcut


def iter_menu_actions(menu):
    for action in menu.actions():
        if action.menu() is not None:
            yield from iter_menu_actions(action.menu())
        elif not action.isSeparator():
            yield action


class TestShortcutUniqueness(AngrManagementTestCase):
    """Collect every window-level binding (menu actions and window-context QShortcuts)."""

    def test_no_ambiguous_shortcuts(self):
        bindings: dict[str, list[str]] = defaultdict(list)

        for menu_action in self.main.menuBar().actions():
            menu = menu_action.menu()
            if menu is None:
                continue
            for action in iter_menu_actions(menu):
                for seq in action.shortcuts():
                    if not seq.isEmpty():
                        bindings[seq.toString()].append(f"menu action '{action.text()}'")

        window_contexts = (Qt.ShortcutContext.WindowShortcut, Qt.ShortcutContext.ApplicationShortcut)
        for shortcut in self.main.findChildren(QShortcut):
            if shortcut.context() in window_contexts and not shortcut.key().isEmpty():
                bindings[shortcut.key().toString()].append("QShortcut")

        duplicates = {seq: owners for seq, owners in bindings.items() if len(owners) > 1}
        assert not duplicates, f"Ambiguous shortcuts: {duplicates}"


if __name__ == "__main__":
    unittest.main()
