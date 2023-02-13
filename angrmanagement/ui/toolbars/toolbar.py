from typing import Optional

from PySide6.QtCore import QSize
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QToolBar

from .toolbar_action import ToolbarAction, ToolbarSplitter


class Toolbar:
    def __init__(self, window, name):
        self.window = window
        self.name = name

        self.actions = []
        self._cached: Optional[QToolBar] = None
        self._cached_actions = {}

    def shutdown(self):
        """
        Prepare for deletion.
        """

    def qtoolbar(self):
        if self._cached is not None:
            return self._cached

        toolbar = QToolBar(self.name, self.window)

        for action in self.actions:
            if action in self._cached_actions:
                act = self._cached_actions[action]
            else:
                act = self._translate_element(toolbar, action)
                if act is not None:
                    self._cached_actions[action] = act

        toolbar.setIconSize(QSize(16, 16))

        self._cached = toolbar
        return toolbar

    @staticmethod
    def _translate_element(toolbar, action):
        if isinstance(action, ToolbarSplitter):
            toolbar.addSeparator()
            return None
        elif isinstance(action, ToolbarAction):
            if action.icon is not None:
                act = QAction(action.icon, action.name, toolbar)
            else:
                act = QAction(action.name, toolbar)
            if action.triggered is not None:
                act.triggered.connect(action.triggered)
            if action.tooltip:
                act.setToolTip(action.tooltip)
            if action.shortcut:
                act.setShortcuts(action.shortcut)
            act.setCheckable(action.checkable)
            toolbar.addAction(act)
            return act
        else:
            raise TypeError("Bad toolbar action", action)

    def add(self, element):
        if self._cached is not None:
            act = self._translate_element(self._cached, element)
            if act is not None:
                self._cached_actions[element] = act

        self.actions.append(element)

    def remove(self, element):
        # REQUIRES object identity
        try:
            act = self._cached_actions[element]
        except KeyError:
            raise ValueError("Element %s not found" % element)

        self.actions.remove(element)
        if self._cached is not None:
            self._cached.removeAction(act)
            del self._cached_actions[element]
