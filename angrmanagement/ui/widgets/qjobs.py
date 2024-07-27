from __future__ import annotations
from angrmanagement.data.jobs import job
import qtawesome as qta

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QSizePolicy, QHeaderView, QProgressBar, QPushButton, QAbstractItemView
from PySide6.QtCore import Qt
from PySide6.QtCore import QSize


from typing import TYPE_CHECKING

class CancelButton(QPushButton):
    '''
        This creates a cancel button for each job in the job views, using the job.cancel()
        method or skipping it from the queue
    '''
    def __init__(self, table: QJobs, new_job: job, workspace):
        super().__init__("Cancel")
        self.workspace = workspace
        
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.clicked.connect(lambda: self.onClick(table, new_job))

    #On cancel button click, the function will check whether to cancel or skip the job
    def onClick(self, table, the_job):
        #Job is cancelled/interrupted if running
        if isinstance(the_job.status, RunningWidget) and the_job in self.workspace.job_manager.jobs:
            self.workspace.job_manager.worker_thread.keyboard_interrupt()
            the_job.cancelled = True
            table.change_job_cancel(the_job)
        #Job is skipped if it's pending
        elif isinstance(the_job.status, PendingWidget):
            the_job.cancelled = True
            table.change_job_cancel(the_job)

class CancelWidget(QWidget):
    '''
        This creates a status widget to show a job's status that it is
        cancelled
    '''
    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        #Constructing cancel icon widget
        self.cancel_widget = qta.IconWidget()
        cancel_icon = qta.icon('ei.remove-sign', color='red')
        self.cancel_widget.setIconSize(QSize(45, 26))
        self.cancel_widget.setIcon(cancel_icon)
    
        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.cancel_widget)

        # Set the layout for the widget
        self.setLayout(hbox)

class FinishWidget(QWidget):
    '''
        This creates a status widget to show a job's status that it is
        Finished
    '''
    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        #Constructing finish icon widget
        self.finish_widget = qta.IconWidget()
        finish_icon = qta.icon('fa.check-circle', color='green')
        self.finish_widget.setIconSize(QSize(45, 30))
        self.finish_widget.setIcon(finish_icon)
    
        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.finish_widget)

        # Set the layout for the widget
        self.setLayout(hbox)

class PendingWidget(QWidget):
    '''
        This creates a status widget to show a job's status that it is
        Pending
    '''
    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        #Constructing pending icon widget
        self.pending_widget = qta.IconWidget()
        pending_icon = qta.icon('fa.clock-o', color='black')
        self.pending_widget.setIconSize(QSize(45, 26))
        self.pending_widget.setIcon(pending_icon)

        hbox = QHBoxLayout()
        hbox.addWidget(self.pending_widget)
        
        # Set the layout for the widget
        self.setLayout(hbox)


class ProgressWidget(QWidget):
    '''
        This creates a progress widget to show a job's progress bar with progression
        of its completion
    '''
    def __init__(self):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setContentsMargins(0, 0, 0, 10)
    
        #Attributes of progress widget: the text for the percentage and the progress bar
        self.text = QLabel("0%")
        self.progressBar = QProgressBar()

        #Properties for the text/percentage
        self.text.setAlignment(Qt.AlignCenter)
        self.text.setFixedSize(45, 26)

        #progress bar properties and behaviors
        self.progressBar.setAlignment(Qt.AlignCenter)
        self.progressBar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.progressBar.setMinimumHeight(20)  # Adjust the minimum height as needed
        self.progressBar.setValue(0)

        #Setting layout and adding both widgets to the entire widget
        hbox = QHBoxLayout()
        hbox.addWidget(self.text)
        hbox.addWidget(self.progressBar)
        self.setLayout(hbox)

class RunningWidget(QWidget):
    '''
        This creates a status widget to show a job's status that it is
        currently running/in progress
    '''
    def __init__(self):
        super().__init__()

        #Create a label for the spinning icon indicating the job is running
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.spin_widget = qta.IconWidget()
        animation = qta.Spin(self.spin_widget, autostart=True)
        spin_icon = qta.icon('fa5s.spinner', color='grey', animation=animation)
        self.spin_widget.setIconSize(QSize(45, 26))
        self.spin_widget.setIcon(spin_icon)

        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.spin_widget)
        
        # Set the layout for the widget
        self.setLayout(hbox)



class QJobs(QTableWidget):
    '''
        This creates a table widget to display all the jobs and
        their status/progression on running the binaries
    '''

    def __init__(self, workspace, parent=None):
        super().__init__(0, 4, parent)  # 0 rows and 4 columns
        self.workspace = workspace
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        
        self.setHorizontalHeaderLabels(["Status", "Name", "Progress", "Cancel"])

        # Set size policy to expand
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)


        #Column and Height Behaviors
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setSortIndicatorShown(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        self.verticalHeader().setDefaultSectionSize(45)

        #Set default column widths, different for each column
        #120
        column_widths = [65, 200, 780, 30]
        for idx, width in enumerate(column_widths):
            self.setColumnWidth(idx, width)

    '''
    PRIVATE METHODS
    '''

    def _add_table_row(self, new_job: job, status): #Status: Any of the status widgets
        '''
        This method creates a row for a job in the jobs view table, 
        takes an argument for a job, and an argument for status(Pending by default)
        '''

        #Assigning the row to the job as an attribute
        new_job.row = self.rowCount()
        self.insertRow(new_job.row)

        #Assigning the status of the job as an attribute and 
        #setting the status widget in the table(column 1)
        new_job.status = status
        self.setCellWidget(new_job.row, 0, new_job.status)

        #Setting the name of the job as a widget in the table(column 2)
        job_name = QTableWidgetItem(new_job.name)
        self.setItem(new_job.row, 1, job_name)
        job_name.setFlags(job_name.flags() & ~Qt.ItemIsEditable)  # Make the item non-editable

        #Assigning the progress bar of the job as an 
        # attribute and setting the progress widget in the table(column 3)
        progressBar = ProgressWidget()
        new_job.progress_bar = progressBar
        self.setCellWidget(new_job.row, 2, new_job.progress_bar)

        #Assigning the cancel button of the job as an attribute and 
        #setting the cancel button widget in the table(column 4)
        new_job.cancel_button = CancelButton(self, new_job, self.workspace)

        #Constructing a seperate container to adjust margins of button
        button_QWidget = QWidget()
        hbox = QHBoxLayout(button_QWidget)
        hbox.setContentsMargins(5, 5, 5, 5)
        hbox.addWidget(new_job.cancel_button)

        self.setCellWidget(new_job.row, 3, button_QWidget)

    '''
    PUBLIC METHODS
    '''

    def add_new_job(self, new_job: job):
        '''
        This method adds a new job to the jobs view table, 
        it only takes an argument for a job to add a row for it in the table
        '''
        pending = PendingWidget()
        self._add_table_row(new_job, pending)
    
    def change_job_progress(self, the_job: job):
        '''
        This method changes the progress percentage and progress bar of a job, 
        only takes the argument for the job to set all the changes
        '''

        the_job.progress_bar.progressBar.setValue(int(the_job.progress_percentage))
        the_job.progress_bar.text.setText(str(int(the_job.progress_percentage)) + "%")
        
        self.setCellWidget(the_job.row, 2, the_job.progress_bar)

    def change_job_cancel(self, the_job: job):
        '''
        This method changes the status of a job in the jobs view table to cancelled,
        only takes the job as an argument
        '''

        the_job.status = CancelWidget()
        self.setCellWidget(the_job.row, 0, the_job.status)

    def change_job_finish(self, the_job: job):
        '''
        This method changes the the status of a job in the jobs view table to 
        finish and sets progress to 100, only takes the job as an argument
        '''

        the_job.status = FinishWidget()
        self.setCellWidget(the_job.row, 0, the_job.status)

        the_job.progress_bar.progressBar.setValue(100)
        the_job.progress_bar.text.setText("100%")

        self.setCellWidget(the_job.row, 2, the_job.progress_bar)

    def change_job_running(self, the_job: job):
        ''' 
        This method changes the status of a job in the jobs view table to running, 
        only takes the job as an argument
        '''

        the_job.status = RunningWidget()
        self.setCellWidget(the_job.row, 0, the_job.status)
