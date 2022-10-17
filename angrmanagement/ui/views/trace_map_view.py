from typing import Optional

from PySide6.QtWidgets import QVBoxLayout
from PySide6.QtCore import QSize

from ..views import BaseView
from ..widgets import QTraceMap


class TraceMapView(BaseView):
    """
    View container for QTraceMap.
    """

    def __init__(self, instance, default_docking_position, *args, **kwargs):
        super().__init__('tracemap', instance, default_docking_position, *args, **kwargs)
        self.base_caption: str = 'Trace Map'
        self.inner_widget: Optional[QTraceMap] = None
        self._init_widgets()

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint:disable=unused-argument
        return QSize(25, 25)

    @staticmethod
    def sizeHint():
        return QSize(25, 25)

    def _init_widgets(self):
        """
        Initialize widgets for this view.
        """
        self.inner_widget = QTraceMap(self.workspace, parent=self)
        lyt = QVBoxLayout()
        lyt.addWidget(self.inner_widget)
        self.setLayout(lyt)
