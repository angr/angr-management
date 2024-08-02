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
        self.main_window = main_window
        self.setAutoClose(False)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setModal(True)
        self.setMinimumDuration(2**31 - 1)

        self.canceled.connect(self.on_cancel)
        self.close()

    def on_cancel(self) -> None:
        if self.main_window.workspace is None:
            return
        for job in self.main_window.workspace.job_manager.jobs:
            if job.blocking:
                self.main_window.workspace.job_manager.interrupt_current_job()
                break
