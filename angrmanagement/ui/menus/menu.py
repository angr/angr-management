"""
Qt rendering of the menus in angrmanagement.present.menus.

``Menu``, ``MenuEntry`` and ``MenuSeparator`` are re-exported from there, so existing imports keep working.
:func:`to_qmenu` builds a QMenu from a ``Menu``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtWidgets import QMenu

from angrmanagement.present.menus import Menu, MenuEntry, MenuSeparator, normalize_entry
from angrmanagement.ui.icons import icon as named_icon

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["Menu", "MenuEntry", "MenuSeparator", "qicon_for", "qkeysequence_for", "to_qmenu", "translate_element"]


def qkeysequence_for(shortcut: Any) -> QKeySequence:
    """A QKeySequence for a shortcut given as a Qt-style string or already as a key sequence."""
    if isinstance(shortcut, QKeySequence):
        return shortcut
    return QKeySequence(shortcut)


def qicon_for(icon: Any) -> QIcon | None:
    """A QIcon for an icon given by name or already as a QIcon."""
    if icon is None or isinstance(icon, QIcon):
        return icon
    return named_icon(icon)


def to_qmenu(menu: Menu, parent=None, extra_entries: Iterable[Any] | None = None) -> QMenu:
    """Build a QMenu holding the entries of ``menu`` followed by ``extra_entries``."""
    qmenu = QMenu(menu.caption, parent) if parent is not None else QMenu(menu.caption)
    for entry in list(menu.entries) + list(extra_entries or ()):
        translate_element(qmenu, entry)
    return qmenu


def translate_element(menu: QMenu, entry: Any, index: int | None = None) -> None:
    """Add one menu element to the QMenu ``menu``, before the action at ``index`` if given."""
    if index is None:
        before = None
    else:
        try:
            before = menu.actions()[index]
        except IndexError:
            before = None

    entry = normalize_entry(entry)

    if isinstance(entry, MenuEntry):
        action = QAction(entry.caption, menu)
        qicon = qicon_for(entry.icon)
        if qicon:
            action.setIcon(qicon)
        action.triggered.connect(entry.action)
        entry.set_qaction(action)

        if entry.shortcut is not None:
            action.setShortcut(qkeysequence_for(entry.shortcut))
        if entry.checkable:
            action.setCheckable(True)
            action.setChecked(entry.checked_initially)

        if before is None:
            menu.addAction(action)
        else:
            menu.insertAction(before, action)
    elif isinstance(entry, MenuSeparator):
        if before is None:
            menu.addSeparator()
        else:
            menu.insertSeparator(before)
    elif isinstance(entry, Menu):
        if before is None:
            menu.addMenu(entry.qmenu())
        else:
            menu.insertMenu(before, entry.qmenu())
    elif isinstance(entry, QMenu):
        if before is None:
            menu.addMenu(entry)
        else:
            menu.insertMenu(before, entry)
    elif isinstance(entry, QAction):
        if before is None:
            menu.addAction(entry)
        else:
            menu.insertAction(before, entry)
    else:
        raise TypeError("Unsupported type", type(entry))
