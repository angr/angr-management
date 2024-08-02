from __future__ import annotations

import datetime
import time
from typing import TYPE_CHECKING

import qtawesome
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QHBoxLayout, QLabel, QProgressBar, QWidget

from angrmanagement.config import Conf
from angrmanagement.ui.dialogs.progress_dialog import ProgressDialog
from angrmanagement.ui.widgets.qicon_label import QIconLabel

if TYPE_CHECKING:
    from angrmanagement.ui.main_window import MainWindow


class QAmStatusBar(QWidget):
    """QAmStatusBar is the status bar at the bottom of the main window."""

    main_window: MainWindow

    _progress_stopwatch_start_time: float
    _progress_message: str
    _progress_percentage: float
    _progress_update_timer: QTimer

    _status_label: QLabel
    _stopwatch_label: QLabel
    _interrupt_job_button: QLabel
    _progress_label: QLabel
    _progress_bar: QProgressBar
    _progress_dialog: ProgressDialog

    def __init__(self, main_window: MainWindow):
        super().__init__()
        self.main_window = main_window

        self._progress_stopwatch_start_time = 0.0
        self._progress_message = ""
        self._progress_percentage = 0
        self._progress_update_timer = QTimer()
        self._progress_update_timer.setSingleShot(False)
        self._progress_update_timer.setInterval(1000)
        self._progress_update_timer.timeout.connect(self._on_progress_update_timer_timeout)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addStretch()

        self._status_label = QLabel()
        self._status_label.hide()
        layout.addWidget(self._status_label)

        self._stopwatch_label = QIconLabel(qtawesome.icon("fa5s.stopwatch", color=Conf.palette_buttontext))
        self._stopwatch_label.hide()
        layout.addWidget(self._stopwatch_label)

        self._interrupt_job_button = QIconLabel(qtawesome.icon("fa5s.times-circle", color=Conf.palette_buttontext))
        self._interrupt_job_button.clicked.connect(lambda: self.main_window.workspace.job_manager.interrupt_current_job)
        self._interrupt_job_button.hide()
        layout.addWidget(self._interrupt_job_button)

        self._progress_label = QLabel()
        self._progress_label.hide()
        layout.addWidget(self._progress_label)

        self._progress_bar = QProgressBar()
        self._progress_bar.setMinimum(0)
        self._progress_bar.setMaximum(100)
        self._progress_bar.setMinimumWidth(100)
        self._progress_bar.setMaximumWidth(100)
        self._progress_bar.hide()
        layout.addWidget(self._progress_bar)

        container_widget = QWidget()
        container_widget.setLayout(layout)
        self.main_window.statusBar().addPermanentWidget(container_widget)

        self._progress_dialog = ProgressDialog(self.main_window)

    def progress(self, status: str, progress: float, reset_stopwatch: bool = False) -> None:
        self._progress_message = status
        self._progress_percentage = progress

        if reset_stopwatch:
            self._progress_stopwatch_start_time = time.time()
        if not self._progress_update_timer.isActive():
            self._progress_update_timer.start()

        self._refresh_progress_progress_message()

    def _refresh_progress_progress_message(self) -> None:
        self._status_label.setText(self._progress_message)
        self._status_label.show()
        self._progress_label.setText(f"{self._progress_percentage:.1f}%")
        self._progress_label.show()
        self._progress_bar.setValue(round(self._progress_percentage))
        self._progress_bar.show()
        elapsed_seconds = int(time.time() - self._progress_stopwatch_start_time)
        if elapsed_seconds > 5:
            self._stopwatch_label.setText(str(datetime.timedelta(seconds=elapsed_seconds)))
            self._stopwatch_label.show()
        self._interrupt_job_button.show()
        self._progress_dialog.setLabelText(self._progress_message)
        self._progress_dialog.setValue(round(self._progress_percentage))

    def _on_progress_update_timer_timeout(self) -> None:
        self._refresh_progress_progress_message()

    def progress_done(self) -> None:
        self._progress_update_timer.stop()
        self._stopwatch_label.hide()
        self._status_label.setText("")
        self._status_label.hide()
        self._progress_label.hide()
        self._progress_bar.hide()
        self._interrupt_job_button.hide()
        self._progress_dialog.hide()
