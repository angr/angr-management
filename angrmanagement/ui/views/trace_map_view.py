from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.views.view import InstanceView
from angrmanagement.ui.widgets import QTraceMap

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class TraceMapView(InstanceView):
    """
    View container for QTraceMap.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("tracemap", workspace, default_docking_position, instance)
        self.base_caption: str = "Trace Map"
        self.inner_widget: QTraceMap | None = None
        self._init_widgets()

    @staticmethod
    def minimumSizeHint():
        return QSize(25, 25)

    @staticmethod
    def sizeHint():
        return QSize(25, 25)

    def _init_widgets(self) -> None:
        """
        Initialize widgets for this view.
        """
        self.inner_widget = QTraceMap(self.instance, parent=self)
        lyt = QVBoxLayout()
        lyt.setContentsMargins(0, 0, 0, 0)
        lyt.addWidget(self.inner_widget)
        self.setLayout(lyt)
