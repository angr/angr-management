from PySide2.QtWidgets import QFrame
from PySide2.QtCore import QSize

class BaseView(QFrame):
    def __init__(self, category: str, workspace, default_docking_position, *args, **kwargs):

        super(BaseView, self).__init__(*args, **kwargs)

        self.workspace = workspace
        self.category = category
        self.default_docking_position = default_docking_position

        self.caption = None

        self.old_width = None
        self.old_height = None
        self.width_hint = -1
        self.height_hint = -1

    def reload(self):
        pass

    def sizeHint(self, *args, **kwargs):
        return QSize(self.width_hint, self.height_hint)

    def resizeEvent(self, event):
        # Update current width
        self.old_width = event.oldSize().width()
        self.old_height = event.oldSize().height()

    def is_shown(self):
        return self.visibleRegion().isEmpty() is False
