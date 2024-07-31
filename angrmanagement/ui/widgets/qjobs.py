from __future__ import annotations

from typing import TYPE_CHECKING

import qtawesome as qta
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from angrmanagement.data.jobs.job import Job
    from angrmanagement.ui.workspace import Workspace


class QIconWidget(qta.IconWidget):
    """QIconWidget is a widget that displays a qtawesome icon."""

    def __init__(self, icon: str, color: str):
        super().__init__()
        self.setIcon(qta.icon(icon, color=color))
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)


class PendingWidget(QIconWidget):
    """PendingWidget represents a pending job icon in the jobs view table."""

    def __init__(self):
        super().__init__("fa.clock-o", "grey")


class RunningWidget(QIconWidget):
    """RunningWidget represents a running job icon in the jobs view table."""

    def __init__(self):
        super().__init__("fa5s.spinner", "grey")


class FinishedWidget(QIconWidget):
    """FinishedWidget represents a finished job icon in the jobs view table."""

    def __init__(self):
        super().__init__("fa.check-circle", "green")


class CancelledWidget(QIconWidget):
    """CancelledWidget represents a cancelled job icon in the jobs view table."""

    def __init__(self):
        super().__init__("ei.remove-sign", "red")


class ProgressWidget(QProgressBar):
    """ProgressWidget represents a progress bar for a job in the jobs view table."""

    label: QLabel

    def __init__(self):
        super().__init__()

        self.label = QLabel("0%")
        self.label.setMinimumHeight(24)

        layout = QHBoxLayout()
        layout.addWidget(self.label)
        layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.setContentsMargins(0, 0, 8, 0)
        self.setLayout(layout)

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setRange(0, 100)
        self.setValue(0)
        self.setMinimumHeight(24)

    def setValue(self, value: int):
        super().setValue(value)
        self.label.setText(f"{value}%")


class CancelButton(QPushButton):
    """Represents a cancel button for a job in the jobs view table."""

    workspace: Workspace

    def __init__(self, table: QJobs, job: Job, workspace):
        super().__init__("Cancel")
        self.workspace = workspace

        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.clicked.connect(lambda: self.onClick(table, job))

    # On cancel button click, the function will check whether to cancel or skip the job
    def onClick(self, table: QJobs, job: Job):
        if self.workspace.job_manager.cancel_job(job):
            table.change_job_cancel(job)


class QJobs(QTableWidget):
    """QJobs displays all the jobs and their status/progression."""

    workspace: Workspace
    content_widget: QWidget
    content_layout: QVBoxLayout

    row_map: dict[Job, int]
    status_map: dict[Job, QWidget]
    progress_bar_map: dict[Job, ProgressWidget]
    cancel_button_map: dict[Job, CancelButton]

    def __init__(self, workspace: Workspace, parent=None):
        super().__init__(0, 4, parent)  # 0 rows and 4 columns
        self.workspace = workspace
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.row_map = {}
        self.status_map = {}
        self.progress_bar_map = {}
        self.cancel_button_map = {}

        self.setHorizontalHeaderLabels(["Status", "Name", "Progress", "Cancel"])

        # Set size policy to expand
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        # Column and Height Behaviors
        self.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        self.horizontalHeader().setSortIndicatorShown(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.verticalHeader().setDefaultSectionSize(24)

        # Set default column widths, different for each column
        column_widths = [16, 200, 780, 65]
        for idx, width in enumerate(column_widths):
            self.setColumnWidth(idx, width)

    # Private Methods

    def _add_table_row(self, job: Job, status: QWidget):
        """_add_table_row is a private method that adds a row to the jobs view table."""

        # Assign the row to the job in the row map
        new_row = self.rowCount()
        self.row_map[job] = new_row
        self.insertRow(new_row)

        # Assign the status of the job as an attribute and set the status widget in the table (column 1)
        self.status_map[job] = status
        self.setCellWidget(new_row, 0, status)

        # Set the name of the job as a widget in the table (column 2)
        job_name = QTableWidgetItem(job.name)
        self.setItem(new_row, 1, job_name)
        job_name.setFlags(job_name.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make the item non-editable

        # Assign the progress bar of the job to the progress bar map and set the
        # progress widget in the table (column 3)
        progress_bar = ProgressWidget()
        self.progress_bar_map[job] = progress_bar
        self.setCellWidget(new_row, 2, progress_bar)

        # Set the cancel button widget in the table (column 4)
        cancel_button = CancelButton(self, job, self.workspace)
        self.cancel_button_map[job] = cancel_button
        self.setCellWidget(new_row, 3, cancel_button)

    # Public Methods

    def add_new_job(self, job: Job):
        """Adds a new job to the jobs view table."""

        pending = PendingWidget()
        self._add_table_row(job, pending)

    def change_job_running(self, job: Job):
        """Changes the status of a job in the jobs view table to running."""

        status = RunningWidget()
        self.status_map[job] = status
        self.setCellWidget(self.row_map[job], 0, status)

    def change_job_progress(self, job: Job):
        """Changes the progress of a job in the jobs view table."""

        self.progress_bar_map[job].setValue(int(job.progress_percentage))

    def change_job_cancel(self, job: Job):
        """Changes the status of a job in the jobs view table to cancelled."""

        status = CancelledWidget()
        self.status_map[job] = status
        self.setCellWidget(self.row_map[job], 0, status)
        self.cancel_button_map[job].setDisabled(True)

    def change_job_finish(self, job: Job):
        """Changes the status of a job in the jobs view table to finished."""

        status = FinishedWidget()
        self.status_map[job] = status
        self.setCellWidget(self.row_map[job], 0, status)

        progress_bar = self.progress_bar_map[job]
        progress_bar.setValue(100)
        self.cancel_button_map[job].setDisabled(True)
