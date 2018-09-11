from PySide2.QtWidgets import QDockWidget


class QSmartDockWidget(QDockWidget):
    def __init__(self, caption, parent=None):
        super(QSmartDockWidget, self).__init__(caption, parent)

        self.old_size = None
        self.original_min = None
        self.original_max = None

    def restore_original_size(self):

        if self.original_min is None or self.original_max is None:
            return

        self.setMinimumWidth(self.original_min.width())
        self.setMinimumHeight(self.original_min.height())
        self.setMaximumWidth(self.original_max.width())
        self.setMaximumHeight(self.original_max.height())
