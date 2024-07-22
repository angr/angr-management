from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QWidget, QVBoxLayout
from angrmanagement.data.instance import Instance
from angrmanagement.ui.widgets.qjobs import qjobs

from typing import TYPE_CHECKING
from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

class jobsView(InstanceView):
    '''
    This creates a view for the jobs view which creates a table to display all the jobs being ran or in queue
    '''
    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("jobs", workspace, default_docking_position, instance)
        self.base_caption = "Jobs"
        self.central_widget = QWidget()
        instance.workspace = workspace

        self._init_widgets(instance)
        self.reload()
    
    def closeEvent(self, event) -> None:
        self._log_widget.close()
        super().closeEvent(event)

    def reload(self) -> None:
        pass

    @staticmethod
    def minimumSizeHint():
        return QSize(0, 50)
    
    #The qjobs widget is initialized in the view, most functions of jobs table is done through qjobs
    def _init_widgets(self, instance) -> None:
        self.q_jobs = qjobs(instance)
        vlayout = QVBoxLayout(self.central_widget)
        vlayout.addWidget(self.q_jobs)
        vlayout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(vlayout)
        