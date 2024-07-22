from __future__ import annotations
from angrmanagement.data.instance import Instance
from angrmanagement.data.jobs import job
from angrmanagement.data.jobs.job import Job
from angrmanagement.config import IMG_LOCATION

from PySide6.QtGui import QPixmap

import qtawesome as qta

import os
import time

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QSizePolicy, QHeaderView, QProgressBar, QPushButton, QAbstractItemView
from PySide6.QtCore import Qt


from typing import TYPE_CHECKING

class CancelButton(QPushButton):
    '''
        This creates a cancel button for each job in the job views, using the job.cancel()
        method or skipping it from the queue
    '''
    def __init__(self, table: qjobs, new_job: job):
        super().__init__("Cancel")
        
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        self.clicked.connect(lambda: self.onClick(table, new_job))

    #On cancel button click, the function will check whether to cancel or skip the job
    def onClick(self, table, the_job):
        #Job is cancelled/interrupted if running
        if isinstance(the_job.status, RunningWidget):
            the_job.cancel()
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

        #Getting Cancel icon location
        error_icon_location = os.path.join(IMG_LOCATION, "error-icon.png")

        # Create a label for the image
        self.image_label = QLabel(self)
        self.image_label.setContentsMargins(0, 0, 0, 0)
        pixmap = QPixmap(error_icon_location)
        scaled_pixmap = pixmap.scaled(25, 25, Qt.KeepAspectRatio, Qt.SmoothTransformation)  # Adjust width and height as needed
        self.image_label.setPixmap(scaled_pixmap)

        self.text = QLabel(' ' + "Cancelled")
    
        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.image_label)
        hbox.addWidget(self.text)

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

        #Getting location for checkmark icon
        check_icon_location = os.path.join(IMG_LOCATION, "circle_green_checkmark.png")

        # Create a label for the image
        self.image_label = QLabel(self)
        self.image_label.setContentsMargins(0, 0, 0, 0)
        pixmap = QPixmap(check_icon_location)
        scaled_pixmap = pixmap.scaled(25, 25, Qt.KeepAspectRatio, Qt.SmoothTransformation)  # Adjust width and height as needed
        self.image_label.setPixmap(scaled_pixmap)

        self.text = QLabel(' ' + "Finished")
    
        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.image_label)
        hbox.addWidget(self.text)

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

        self.pending_widget = qta.IconWidget()
        pending_icon = qta.icon('fa.clock-o', color='black')
        self.pending_widget.setIcon(pending_icon)

        self.text = QLabel(' ' + 'Pending')
        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.pending_widget)
        hbox.addWidget(self.text)
        
        # Set the layout for the widget
        self.setLayout(hbox)


class progressWidget(QWidget):
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
        self.spin_widget.setIcon(spin_icon)

        self.text = QLabel(' ' + 'In Progress')

        # Create a horizontal layout and add the labels
        hbox = QHBoxLayout()
        hbox.addWidget(self.spin_widget)
        hbox.addWidget(self.text)
        
        # Set the layout for the widget
        self.setLayout(hbox)



class qjobs(QTableWidget):
    '''
        This creates a table widget to display all the jobs and
        their status/progression on running the binaries
    '''

    check_icon_location = os.path.join(IMG_LOCATION, "circle_green_checkmark.png")

    def __init__(self, instance: Instance, parent=None):
        super().__init__(0, 4, parent)  # 0 rows and 4 columns
        self.jobs = instance.jobs
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
        column_widths = [120, 200, 780, 30]
        for idx, width in enumerate(column_widths):
            self.setColumnWidth(idx, width)

##### PRIVATE METHOD

    #This method creates a row for a job in the jobs view table, takes an argument for a job, and an argument for status(Pending by default)
    def __add_table_row__(self, new_job: job, status): #Status: Any of the status widgets

        #Assigning the row to the job as an attribute
        new_job.row = self.rowCount()
        self.insertRow(new_job.row)

        #Assigning the status of the job as an attribute and setting the status widget in the table(column 1)
        new_job.status = status
        self.setCellWidget(new_job.row, 0, new_job.status)

        #Setting the name of the job as a widget in the table(column 2)
        job_name = QTableWidgetItem(new_job.name)
        self.setItem(new_job.row, 1, job_name)
        job_name.setFlags(job_name.flags() & ~Qt.ItemIsEditable)  # Make the item non-editable

        #Assigning the progress bar of the job as an attribute and setting the progress widget in the table(column 3)
        progressBar = progressWidget()
        new_job.progress_bar = progressBar
        self.setCellWidget(new_job.row, 2, new_job.progress_bar)

        #Assigning the cancel button of the job as an attribute and setting the cancel button widget in the table(column 4)
        new_job.cancel_button = CancelButton(self, new_job)

        #Constructing a seperate container to adjust margins of button
        button_QWidget = QWidget()
        hbox = QHBoxLayout(button_QWidget)
        hbox.setContentsMargins(5, 5, 5, 5)
        hbox.addWidget(new_job.cancel_button)

        self.setCellWidget(new_job.row, 3, button_QWidget)

##### PUBLIC METHODS

    #This method adds a new job to the jobs view table, it only takes an argument for a job to add a row for it in the table
    def add_new_job(self, new_job: job):
        pending = PendingWidget()
        self.__add_table_row__(new_job, pending)
    
    #This method changes the progress percentage and progress bar of a job, only takes the argument for the job to set all the changes
    def change_job_progress(self, the_job: job):

        #Checks for original/previous widget to replace and remove(progress widget)
        existing_widget = self.cellWidget(the_job.row, 2)
        if existing_widget is not None:
            existing_widget.deleteLater()

        the_job.progress_bar = progressWidget()

        the_job.progress_bar.progressBar.setValue(int(the_job.progress_percentage))
        the_job.progress_bar.text.setText(str(int(the_job.progress_percentage)) + "%")

        
        self.setCellWidget(the_job.row, 2, the_job.progress_bar)

    #This method changes the status of a job in the jobs view table to cancelled, only takes the job as an argument
    def change_job_cancel(self, the_job: job):

        #Checks for original/previous widget to replace and remove(cancel widget)
        existing_widget = self.cellWidget(the_job.row, 0)
        if existing_widget is not None:
            existing_widget.deleteLater()

        the_job.status = CancelWidget()
        self.setCellWidget(the_job.row, 0, the_job.status)

    #This method changes the the status of a job in the jobs view table to finished and sets progress to 100, only takes the job as an argument
    def change_job_finish(self, the_job: job):

        #Checks for original/previous widget to replace and remove(status widget)
        existing_widget = self.cellWidget(the_job.row, 0)
        if existing_widget is not None:
            existing_widget.deleteLater()

        the_job.status = FinishWidget()
        self.setCellWidget(the_job.row, 0, the_job.status)

        #Checks for original/previous widget to replace and remove(progress widget)
        existing_widget = self.cellWidget(the_job.row, 2)
        if existing_widget is not None:
            existing_widget.deleteLater()

        the_job.progress_bar = progressWidget()

        the_job.progress_bar.progressBar.setValue(100)
        the_job.progress_bar.text.setText("100%")

        self.setCellWidget(the_job.row, 2, the_job.progress_bar)

    #This method changes the status of a job in the jobs view table to running, only takes the job as an argument
    def change_job_running(self, the_job: job):

        #Checks for original/previous widget to replace and remove
        existing_widget = self.cellWidget(the_job.row, 0)
        if existing_widget is not None:
            existing_widget.deleteLater()

        the_job.status = RunningWidget()
        self.setCellWidget(the_job.row, 0, the_job.status)
