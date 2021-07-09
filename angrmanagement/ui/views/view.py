from typing import TYPE_CHECKING

import PySide2.QtGui
from PySide2.QtWidgets import QFrame
from PySide2.QtCore import QSize

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class BaseView(QFrame):
    def __init__(self, category: str, workspace, default_docking_position, *args, **kwargs):

        super(BaseView, self).__init__(*args, **kwargs)

        self.workspace: 'Workspace' = workspace
        self.category = category
        self.default_docking_position = default_docking_position

        self.old_width = None
        self.old_height = None
        self.width_hint = -1
        self.height_hint = -1
        self.index = 1

    def focus(self):
        self.workspace.view_manager.raise_view(self)

    def reload(self):
        pass

    def sizeHint(self):
        return QSize(self.width_hint, self.height_hint)

    def resizeEvent(self, event):
        # Update current width
        self.old_width = event.oldSize().width()
        self.old_height = event.oldSize().height()

    def is_shown(self):
        return self.visibleRegion().isEmpty() is False

    def closeEvent(self, event:PySide2.QtGui.QCloseEvent):
        self.workspace.view_manager.remove_view(self)
        event.accept()

    #
    # Properties
    #

    @property
    def caption(self):
        return f'{self.base_caption}-{self.index}'
