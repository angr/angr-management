from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.widgets.qjobs import QJobs

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class JobsView(InstanceView):
    """JobsView displays all pending, running, and finished jobs in the project."""

    qjobs: QJobs

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("jobs", workspace, default_docking_position, instance)
        self.base_caption = "Jobs"

        # The QJobs widget is initialized in the view, most functions of jobs table is done through QJobs
        self.qjobs = QJobs(workspace)
        vlayout = QVBoxLayout()
        vlayout.addWidget(self.qjobs)
        vlayout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(vlayout)
        self.reload()

    def closeEvent(self, event) -> None:
        self.qjobs.close()
        super().closeEvent(event)

    def reload(self) -> None:
        pass

    @staticmethod
    def minimumSizeHint():
        return QSize(0, 50)
