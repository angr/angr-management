from PySide2.QtWidgets import QToolBar, QAction
from PySide2.QtCore import QSize


class ToolbarAction(object):
    def __init__(self, icon, name, tooltip, triggered):
        self.icon = icon
        self.name = name
        self.tooltip = tooltip
        self.triggered = triggered


class ToolbarSplitter(ToolbarAction):
    def __init__(self):
        super(ToolbarSplitter, self).__init__(None, None, None, None)


class Toolbar(object):
    def __init__(self, window, name):
        self.window = window
        self.name = name

        self.actions = [ ]

    def qtoolbar(self):
        toolbar = QToolBar(self.name, self.window)

        for action in self.actions:
            if isinstance(action, ToolbarSplitter):
                toolbar.addSeparator()
            else:
                if action.icon is not None:
                    act = QAction(action.icon, action.name, toolbar)
                else:
                    act = QAction(action.name, toolbar)
                if action.triggered is not None:
                    act.triggered.connect(action.triggered)
                if action.tooltip:
                    act.setToolTip(action.tooltip)
                toolbar.addAction(act)

        toolbar.setIconSize(QSize(16, 16))

        return toolbar
