"""
Menus as data.

A :class:`Menu` is a caption and a list of entries: :class:`MenuEntry` (a caption and a callable),
:class:`MenuSeparator` and nested menus. Shortcuts are Qt-style strings such as ``"Ctrl+Shift+P"`` and icons are names
such as ``"file-open"``; each frontend turns them into its own objects. ``Menu.qmenu()`` builds a QMenu through
``angrmanagement.ui.menus.menu`` and imports Qt only when it is called.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.logic.signal import max_positional_args

if TYPE_CHECKING:
    from collections.abc import Iterable


class MenuEntry:
    """
    One item of a menu.

    :param caption:     The text, with ``&`` before the mnemonic letter.
    :param action:      Called when the entry is chosen; a checkable entry's action may take the new checked state.
    :param shortcut:    The key sequence as a Qt-style string, such as ``"Ctrl+O"``. A QKeySequence is accepted too.
    :param icon:        The icon's name (see angrmanagement.ui.icons). A QIcon is accepted too.
    :param role:        Kept for compatibility; no frontend uses it.
    """

    _qaction: Any

    def __init__(
        self,
        caption,
        action,
        shortcut=None,
        checkable: bool = False,
        checked: bool = False,
        enabled: bool = True,
        key=None,
        role: Any = None,
        icon: Any = None,
    ) -> None:
        self.caption = caption
        self.action = action
        self.shortcut = shortcut
        self.checkable = checkable
        self.checked_initially = checked
        self.enabled = enabled
        self.key = key
        self.icon = icon

        self._checked = checked
        self._qaction = None
        self._role = role

    @property
    def text(self) -> str:
        """The caption without its mnemonic markers."""
        return strip_mnemonic(self.caption)

    @property
    def mnemonic(self) -> str | None:
        """The letter after the first single ``&`` in the caption, in lower case."""
        return mnemonic_of(self.caption)

    def set_qaction(self, qaction) -> None:
        """Bind the entry to the frontend object that shows it; it gets the entry's enabled and checked states."""
        self._qaction = qaction
        self._enable(self.enabled)

    def enable(self) -> None:
        self._enable(True)

    def disable(self) -> None:
        self._enable(False)

    def _enable(self, b: bool) -> None:
        self.enabled = b
        if self._qaction is not None:
            self._qaction.setEnabled(b)

    @property
    def checked(self) -> bool:
        if not self.checkable:
            return False
        if self._qaction is not None:
            return self._qaction.isChecked()
        return self._checked

    @checked.setter
    def checked(self, checked: bool) -> None:
        self._checked = checked
        if self._qaction is not None:
            self._qaction.setChecked(checked)

    def trigger(self) -> None:
        """Choose the entry, as a click does: toggle a checkable entry, then run the action."""
        if not self.enabled:
            return
        if self.checkable:
            self.checked = not self.checked
            if max_positional_args(self.action) != 0:
                self.action(self.checked)
                return
        self.action()


class MenuSeparator:
    """A line between groups of entries."""

    def __init__(self) -> None:
        pass


class Menu:
    """
    A menu: a caption and its entries.

    ``children`` and :meth:`add` take entries, separators, menus, ``None`` (a separator), a ``(caption, callable)``
    tuple (an entry) or a ``(caption, children)`` tuple (a submenu).
    """

    def __init__(self, caption, children=(), parent=None) -> None:
        self.parent = parent
        self.caption = caption

        self.entries: list[Any] = []
        self._keyed_entries = None

        self._qmenu = None

        for child in children:
            self.add(child)

    @property
    def text(self) -> str:
        """The caption without its mnemonic markers."""
        return strip_mnemonic(self.caption)

    @property
    def mnemonic(self) -> str | None:
        """The letter after the first single ``&`` in the caption, in lower case."""
        return mnemonic_of(self.caption)

    def items(self, extra_entries: Iterable[Any] | None = None) -> list[MenuEntry | MenuSeparator | Menu | Any]:
        """
        The entries to show, in order, with ``None`` and tuples turned into separators, entries and menus. Objects of
        other types (a frontend's own menus or actions) are passed through.
        """
        return [normalize_entry(entry) for entry in list(self.entries) + list(extra_entries or ())]

    def qmenu(self, extra_entries=None, cached: bool = True):
        """The menu as a QMenu (imports Qt). A menu built without extra entries is kept and returned next time."""
        from angrmanagement.ui.menus.menu import to_qmenu  # pylint:disable=import-outside-toplevel

        if cached and not extra_entries and self._qmenu is not None:
            return self._qmenu
        menu = to_qmenu(self, self.parent, extra_entries)
        if not extra_entries:
            self._qmenu = menu
        return menu

    @staticmethod
    def translate_element(menu, entry, index=None) -> None:
        """Add ``entry`` to the QMenu ``menu`` (imports Qt)."""
        from angrmanagement.ui.menus.menu import translate_element  # pylint:disable=import-outside-toplevel

        translate_element(menu, entry, index)

    def add(self, action, index=None) -> None:
        if index is None:
            index = len(self.entries)
        self.entries.insert(index, action)
        if self._qmenu is not None:
            self.translate_element(self._qmenu, action, index)

    def remove(self, action) -> None:
        self.entries.remove(action)
        if self._qmenu is not None and isinstance(action, MenuEntry) and action._qaction is not None:
            self._qmenu.removeAction(action._qaction)


def normalize_entry(entry: Any) -> MenuEntry | MenuSeparator | Menu | Any:
    """Turn ``None`` into a separator and a two-item tuple into an entry or a submenu; return anything else as is."""
    if entry is None:
        return MenuSeparator()
    if type(entry) is tuple and len(entry) == 2:
        if callable(entry[1]):
            return MenuEntry(*entry)
        if hasattr(entry[1], "__iter__"):
            return Menu(*entry)
    return entry


def strip_mnemonic(caption: str) -> str:
    """``"&File"`` becomes ``"File"``; ``"&&"`` becomes ``"&"``."""
    return caption.replace("&&", "\0").replace("&", "").replace("\0", "&")


def mnemonic_of(caption: str) -> str | None:
    """The lower-case letter after the first single ``&`` in ``caption``, or None."""
    idx = 0
    while True:
        idx = caption.find("&", idx)
        if idx < 0 or idx + 1 >= len(caption):
            return None
        if caption[idx + 1] == "&":
            idx += 2
            continue
        return caption[idx + 1].lower()


def walk_entries(menu: Menu) -> Iterable[tuple[list[str], MenuEntry]]:
    """Every entry under ``menu`` with the captions of the submenus that lead to it."""

    def walk(current: Menu, path: list[str]):
        for item in current.items():
            if isinstance(item, Menu):
                yield from walk(item, [*path, item.text])
            elif isinstance(item, MenuEntry):
                yield path, item

    yield from walk(menu, [])


def find_entry(menu: Menu, caption: str) -> MenuEntry | None:
    """The first entry under ``menu`` whose caption, without mnemonic markers, is ``caption``."""
    for _, entry in walk_entries(menu):
        if entry.text == caption:
            return entry
    return None
