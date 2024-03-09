from typing import TYPE_CHECKING, Optional

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu

if TYPE_CHECKING:
    from PySide6.QtGui import QIcon


class MenuEntry:
    _qaction: Optional[QAction]

    def __init__(
        self,
        caption,
        action,
        shortcut=None,
        checkable=False,
        checked=False,
        enabled=True,
        key=None,
        role: QAction.MenuRole = QAction.MenuRole.NoRole,
        icon: Optional["QIcon"] = None,
    ):
        self.caption = caption
        self.action = action
        self.shortcut = shortcut
        self.checkable = checkable
        self.checked_initially = checked
        self.enabled = enabled
        self.key = key
        self.icon = icon

        self._qaction = None
        self._role = role

    def set_qaction(self, qaction: QAction):
        self._qaction = qaction
        self._enable(self.enabled)

    def enable(self):
        self._enable(True)

    def disable(self):
        self._enable(False)

    def _enable(self, b: bool):
        self.enabled = b
        if self._qaction is not None:
            self._qaction.setEnabled(b)

    @property
    def checked(self):
        if self._qaction is None or not self.checkable:
            return False
        return self._qaction.isChecked()

    @checked.setter
    def checked(self, checked: bool):
        if self._qaction is not None:
            self._qaction.setChecked(checked)


class MenuSeparator:
    def __init__(self):
        pass


class Menu:
    def __init__(self, caption, children=(), parent=None):
        self.parent = parent
        self.caption = caption

        self.entries = []
        self._keyed_entries = None

        self._qmenu: Optional[QMenu] = None

        for child in children:
            self.add(child)

    def action_by_key(self, key):
        if not self._keyed_entries:
            self._keyed_entries = {ent.key: ent for ent in self.entries if isinstance(ent, MenuEntry)}
        return self._keyed_entries.get(key, None)

    def qmenu(self, extra_entries=None, cached=True):
        if extra_entries is None:
            extra_entries = []

        if cached and not extra_entries and self._qmenu is not None:
            # in order to use the cached result, must not have extra entries
            return self._qmenu

        menu = QMenu(self.caption, self.parent) if self.parent is not None else QMenu(self.caption)

        for entry in self.entries + extra_entries:
            self.translate_element(menu, entry)

        # in order to cache the result, must not have extra entries
        if not extra_entries:
            self._qmenu = menu

        return menu

    @staticmethod
    def translate_element(menu, entry, index=None):
        if index is None:
            before = None
        else:
            try:
                before = menu.actions()[index]
            except IndexError:
                before = None

        if entry is None:
            entry = MenuSeparator()
        elif type(entry) is tuple and len(entry) == 2 and callable(entry[1]):
            entry = MenuEntry(*entry)
        elif type(entry) is tuple and len(entry) == 2 and hasattr(entry[1], "__iter__"):
            entry = Menu(*entry)

        if isinstance(entry, MenuEntry):
            action = QAction(entry.caption, menu)
            if entry.icon:
                action.setIcon(entry.icon)
            action.triggered.connect(entry.action)
            entry.set_qaction(action)

            if entry.shortcut is not None:
                action.setShortcut(entry.shortcut)
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

    def add(self, action, index=None):
        if index is None:
            index = len(self.entries)
        self.entries.insert(index, action)
        if self._qmenu is not None:
            self.translate_element(self._qmenu, action, index)

    def remove(self, action):
        self.entries.remove(action)
        if self._qmenu is not None and isinstance(action, MenuEntry):
            self._qmenu.removeAction(action._qaction)
