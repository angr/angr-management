from __future__ import annotations

import qtawesome as qta
from PySide6.QtCore import QSize, Qt
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

from angrmanagement.data.jobs.job import Job


class CancelButton(QPushButton):
    """
    This creates a cancel button for each job in the job views, using the job.cancel()
    method or skipping it from the queue
    """

    def __init__(self, table: QJobs, job: Job, workspace):
        super().__init__("Cancel")
        self.workspace = workspace

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.clicked.connect(lambda: self.onClick(table, job))

    # On cancel button click, the function will check whether to cancel or skip the job
    def onClick(self, table, job):
        # Job is cancelled/interrupted if running
        if isinstance(job.status, RunningWidget) and job in self.workspace.job_manager.jobs:
            self.workspace.job_manager.worker_thread.keyboard_interrupt()
            job.cancelled = True
            table.change_job_cancel(job)
        # Job is skipped if it's pending
        elif isinstance(job.status, PendingWidget):
            job.cancelled = True
            table.change_job_cancel(job)


class CancelledWidget(QWidget):
    """
    This creates a status widget to show a job's status that it is
    cancelled
    """

    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Constructing cancel icon widget
        self.cancel_widget = qta.IconWidget()
        cancel_icon = qta.icon("ei.remove-sign", color="red")
        self.cancel_widget.setIconSize(QSize(45, 26))
        self.cancel_widget.setIcon(cancel_icon)

        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.cancel_widget)

        # Set the layout for the widget
        self.setLayout(hbox)


class FinishedWidget(QWidget):
    """
    This creates a status widget to show a job's status that it is
    Finished
    """

    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Constructing finish icon widget
        self.finish_widget = qta.IconWidget()
        finish_icon = qta.icon("fa.check-circle", color="green")
        self.finish_widget.setIconSize(QSize(45, 30))
        self.finish_widget.setIcon(finish_icon)

        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.finish_widget)

        # Set the layout for the widget
        self.setLayout(hbox)


class PendingWidget(QWidget):
    """
    This creates a status widget to show a job's status that it is
    Pending
    """

    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Constructing pending icon widget
        self.pending_widget = qta.IconWidget()
        pending_icon = qta.icon("fa.clock-o", color="black")
        self.pending_widget.setIconSize(QSize(45, 26))
        self.pending_widget.setIcon(pending_icon)

        hbox = QHBoxLayout()
        hbox.addWidget(self.pending_widget)

        # Set the layout for the widget
        self.setLayout(hbox)


class ProgressWidget(QWidget):
    """
    This creates a progress widget to show a job's progress bar with progression
    of its completion
    """

    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setContentsMargins(0, 0, 0, 10)

        # Attributes of progress widget: the text for the percentage and the progress bar
        self.text = QLabel("0%")
        self.progressBar = QProgressBar()

        # Properties for the text/percentage
        self.text.setAlignment(Qt.AlignCenter)
        self.text.setFixedSize(45, 26)

        # progress bar properties and behaviors
        self.progressBar.setAlignment(Qt.AlignCenter)
        self.progressBar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.progressBar.setMinimumHeight(20)  # Adjust the minimum height as needed
        self.progressBar.setValue(0)

        # Setting layout and adding both widgets to the entire widget
        hbox = QHBoxLayout()
        hbox.addWidget(self.text)
        hbox.addWidget(self.progressBar)
        self.setLayout(hbox)


class RunningWidget(QWidget):
    """
    This creates a status widget to show a job's status that it is
    currently running/in progress
    """

    def __init__(self):
        super().__init__()

        # Create a label for the spinning icon indicating the job is running
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.spin_widget = qta.IconWidget()
        animation = qta.Spin(self.spin_widget, autostart=True)
        spin_icon = qta.icon("fa5s.spinner", color="grey", animation=animation)
        self.spin_widget.setIconSize(QSize(45, 26))
        self.spin_widget.setIcon(spin_icon)

        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.spin_widget)

        # Set the layout for the widget
        self.setLayout(hbox)


class QJobs(QTableWidget):
    """
    This creates a table widget to display all the jobs and
    their status/progression on running the binaries
    """

    def __init__(self, workspace, parent=None):
        super().__init__(0, 4, parent)  # 0 rows and 4 columns
        self.workspace = workspace
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)

        self.setHorizontalHeaderLabels(["Status", "Name", "Progress", "Cancel"])

        # Set size policy to expand
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

        # Column and Height Behaviors
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setSortIndicatorShown(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setDefaultSectionSize(45)

        # Set default column widths, different for each column
        # 120
        column_widths = [65, 200, 780, 30]
        for idx, width in enumerate(column_widths):
            self.setColumnWidth(idx, width)

    # Private Methods

    def _add_table_row(self, job: Job, status):  # Status: Any of the status widgets
        """
        This method creates a row for a job in the jobs view table,
        takes an argument for a job, and an argument for status(Pending by default)
        """

        # Assigning the row to the job as an attribute
        job.row = self.rowCount()
        self.insertRow(job.row)

        # Assigning the status of the job as an attribute and
        # setting the status widget in the table(column 1)
        job.status = status
        self.setCellWidget(job.row, 0, job.status)

        # Setting the name of the job as a widget in the table(column 2)
        job_name = QTableWidgetItem(job.name)
        self.setItem(job.row, 1, job_name)
        job_name.setFlags(job_name.flags() & ~Qt.ItemIsEditable)  # Make the item non-editable

        # Assigning the progress bar of the job as an
        # attribute and setting the progress widget in the table(column 3)
        progressBar = ProgressWidget()
        job.progress_bar = progressBar
        self.setCellWidget(job.row, 2, job.progress_bar)

        # Assigning the cancel button of the job as an attribute and
        # setting the cancel button widget in the table(column 4)
        job.cancel_button = CancelButton(self, job, self.workspace)

        # Constructing a seperate container to adjust margins of button
        button_QWidget = QWidget()
        hbox = QHBoxLayout(button_QWidget)
        hbox.setContentsMargins(5, 5, 5, 5)
        hbox.addWidget(job.cancel_button)

        self.setCellWidget(job.row, 3, button_QWidget)

    # Public Methods

    def add_new_job(self, job: Job):
        """
        This method adds a new job to the jobs view table,
        it only takes an argument for a job to add a row for it in the table
        """
        pending = PendingWidget()
        self._add_table_row(job, pending)

    def change_job_progress(self, job: Job):
        """
        This method changes the progress percentage and progress bar of a job,
        only takes the argument for the job to set all the changes
        """

        job.progress_bar.progressBar.setValue(int(job.progress_percentage))
        job.progress_bar.text.setText(str(int(job.progress_percentage)) + "%")

        self.setCellWidget(job.row, 2, job.progress_bar)

    def change_job_cancel(self, job: Job):
        """
        This method changes the status of a job in the jobs view table to cancelled,
        only takes the job as an argument
        """

        job.status = CancelledWidget()
        self.setCellWidget(job.row, 0, job.status)

    def change_job_finish(self, job: Job):
        """
        This method changes the the status of a job in the jobs view table to
        finish and sets progress to 100, only takes the job as an argument
        """

        job.status = FinishedWidget()
        self.setCellWidget(job.row, 0, job.status)

        job.progress_bar.progressBar.setValue(100)
        job.progress_bar.text.setText("100%")

        self.setCellWidget(job.row, 2, job.progress_bar)

    def change_job_running(self, job: Job):
        """
        This method changes the status of a job in the jobs view table to running,
        only takes the job as an argument
        """

        job.status = RunningWidget()
        self.setCellWidget(job.row, 0, job.status)
