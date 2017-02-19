
from PySide.QtGui import QMenu


class MenuEntry(object):
    def __init__(self, caption, action, shortcut=None):
        self.caption = caption
        self.action = action
        self.shortcut = shortcut


class MenuSeparator(object):
    def __init__(self):
        pass


class Menu(object):
    def __init__(self, window, caption):

        self.window = window
        self.caption = caption

        self.entries = [ ]

        self._qmenu = None  # cached QMenu object

    def qmenu(self):
        if self._qmenu is not None:
            return self._qmenu

        menu = QMenu(self.caption, self.window)

        for entry in self.entries:
            if isinstance(entry, MenuEntry):
                action = menu.addAction(entry.caption, entry.action)
                if entry.shortcut is not None:
                    action.setShortcut(entry.shortcut)
            elif isinstance(entry, MenuSeparator):
                menu.addSeparator()
            else:
                raise Exception('Unsupported type %s' % type(entry))

        self._qmenu = menu

        return menu
