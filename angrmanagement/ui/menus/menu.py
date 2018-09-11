from PySide2.QtWidgets import QMenu, QAction


class MenuEntry(object):
    def __init__(self, caption, action, shortcut=None, checkable=False, checked=False):
        self.caption = caption
        self.action = action
        self.shortcut = shortcut
        self.checkable = checkable
        self.checked_initially = checked

        self._qaction = None

    @property
    def qaction(self):
        return self._qaction

    @qaction.setter
    def qaction(self, v):
        self._qaction = v

    @property
    def checked(self):
        if self._qaction is None or not self.checkable:
            return False
        return self._qaction.isChecked()


class MenuSeparator(object):
    def __init__(self):
        pass


class Menu(object):
    def __init__(self, caption, parent=None):

        self.parent = parent
        self.caption = caption

        self.entries = [ ]

        self._qmenu = None  # cached QMenu object

    def qmenu(self):
        if self._qmenu is not None:
            return self._qmenu

        if self.parent is not None:
            menu = QMenu(self.caption, self.parent)
        else:
            menu = QMenu(self.caption)

        for entry in self.entries:
            if isinstance(entry, MenuEntry):
                action = menu.addAction(entry.caption, entry.action)  # type: QAction
                if entry.shortcut is not None:
                    action.setShortcut(entry.shortcut)
                if entry.checkable:
                    action.setCheckable(True)
                    action.setChecked(entry.checked_initially)
                entry.qaction = action
            elif isinstance(entry, MenuSeparator):
                menu.addSeparator()
            else:
                raise Exception('Unsupported type %s' % type(entry))

        self._qmenu = menu

        return menu
