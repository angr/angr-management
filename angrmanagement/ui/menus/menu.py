from PySide2.QtWidgets import QMenu, QAction


class MenuEntry:
    def __init__(self, caption, action, shortcut=None, checkable=False, checked=False, enabled=True, key=None):
        self.caption = caption
        self.action = action
        self.shortcut = shortcut
        self.checkable = checkable
        self.checked_initially = checked
        self.default_enabled = enabled
        self.key = key

        self.qaction = None

    def enable(self):
        if self.qaction is not None:
            self.qaction.setDisabled(False)

    def disable(self):
        if self.qaction is not None:
            self.qaction.setDisabled(True)

    @property
    def checked(self):
        if self.qaction is None or not self.checkable:
            return False
        return self.qaction.isChecked()


class MenuSeparator:
    def __init__(self):
        pass


class Menu:
    def __init__(self, caption, children=(), parent=None):

        self.parent = parent
        self.caption = caption

        self.entries = [ ]
        self._keyed_entries = None

        self._qmenu = None  # type: QMenu

        for child in children:
            self.add(child)

    def action_by_key(self, key):
        if not self._keyed_entries:
            self._keyed_entries = dict((ent.key, ent) for ent in
                    self.entries if isinstance(ent, MenuEntry))
        return self._keyed_entries.get(key, None)

    def qmenu(self, extra_entries=None, cached=True):
        if extra_entries is None:
            extra_entries = []

        if cached and not extra_entries and self._qmenu is not None:
            # in order to use the cached result, must not have extra entries
            return self._qmenu

        if self.parent is not None:
            menu = QMenu(self.caption, self.parent)
        else:
            menu = QMenu(self.caption)

        for entry in self.entries + extra_entries:
            self.translate_element(menu, entry)

        # in order to cache the result, must not have extra entries
        if not extra_entries:
            self._qmenu = menu

        return menu

    @staticmethod
    def translate_element(menu, entry):
        if entry is None:
            entry = MenuSeparator()
        elif type(entry) is tuple and len(entry) == 2 and callable(entry[1]):
            entry = MenuEntry(*entry)
        elif type(entry) is tuple and len(entry) == 2 and hasattr(entry[1], '__iter__'):
            entry = Menu(*entry)

        if isinstance(entry, MenuEntry):
            action: QAction = menu.addAction(entry.caption, entry.action)
            if entry.shortcut is not None:
                action.setShortcut(entry.shortcut)
            if entry.checkable:
                action.setCheckable(True)
                action.setChecked(entry.checked_initially)
            if not entry.default_enabled:
                action.setDisabled(True)
            entry.qaction = action
        elif isinstance(entry, MenuSeparator):
            menu.addSeparator()
        elif isinstance(entry, Menu):
            menu.addMenu(entry.qmenu())
        elif isinstance(entry, QMenu):
            menu.addMenu(entry)
        elif isinstance(entry, QAction):
            menu.addAction(entry)
        else:
            raise TypeError('Unsupported type', type(entry))

    def add(self, action):
        self.entries.append(action)
        if self._qmenu is not None:
            self.translate_element(self._qmenu, action)

    def remove(self, action):
        self.entries.remove(action)
        if self._qmenu is not None and type(action) is MenuEntry:
            self._qmenu.removeAction(action.qaction)
