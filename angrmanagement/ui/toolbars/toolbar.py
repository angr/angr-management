from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QToolBar

from angrmanagement.ui.menus.menu import qicon_for

from .toolbar_action import ToolbarAction, ToolbarSplitter


class Toolbar:
    def __init__(self, window, name: str) -> None:
        self.window = window
        self.name = name

        self.actions = []
        self._cached: QToolBar | None = None
        self._cached_actions = {}

    def shutdown(self) -> None:
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
            # an icon may be given by name, as plugins' TOOLBAR_BUTTONS can
            qicon = qicon_for(action.icon)
            act = QAction(qicon, action.name, toolbar) if qicon is not None else QAction(action.name, toolbar)
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

    def add(self, element) -> None:
        if self._cached is not None:
            act = self._translate_element(self._cached, element)
            if act is not None:
                self._cached_actions[element] = act

        self.actions.append(element)

    def remove(self, element):
        # REQUIRES object identity
        try:
            act = self._cached_actions[element]
        except KeyError as ex:
            raise ValueError(f"Element {element} not found") from ex

        self.actions.remove(element)
        if self._cached is not None:
            self._cached.removeAction(act)
            del self._cached_actions[element]
