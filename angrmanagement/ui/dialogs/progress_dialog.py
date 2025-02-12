from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QProgressDialog

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class ProgressDialog(QProgressDialog):
    """ProgressDialog is a dialog that shows the progress of a job on top of the main window."""

    main_window: MainWindow

    def __init__(self, main_window: MainWindow):
        super().__init__("Waiting...", "Cancel", 0, 100, parent=main_window)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setModal(True)
        self.setMinimumDuration(0)
        self.canceled.disconnect()
        self.reset()
