from PySide2.QtWidgets import QDockWidget


class QSmartDockWidget(QDockWidget):
    """
    Wrapper class for dock widgets.
    """

    def __init__(self, caption, parent=None, on_close=None, on_raise=None):
        super().__init__(caption, parent)

        self.old_size = None
        self.original_min = None
        self.original_max = None
        self._on_close = on_close
        self._on_raise = on_raise

    def restore_original_size(self):

        if self.original_min is None or self.original_max is None:
            return

        self.setMinimumWidth(self.original_min.width())
        self.setMinimumHeight(self.original_min.height())
        self.setMaximumWidth(self.original_max.width())
        self.setMaximumHeight(self.original_max.height())

    def closeEvent(self, event):  # pylint: disable=unused-argument
        if self._on_close is not None:
            self._on_close()
        self.widget().close()

    def raise_(self):
        if self._on_raise is not None:
            self._on_raise()
        super().raise_()
