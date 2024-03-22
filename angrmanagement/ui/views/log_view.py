from __future__ import annotations

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QHBoxLayout

from angrmanagement.ui.widgets.qlog_widget import QLogWidget

from .view import InstanceView


class LogView(InstanceView):
    """
    Log view displays logging output.
    """

    def __init__(self, workspace, instance, default_docking_position):
        super().__init__("log", workspace, default_docking_position, instance)

        self.base_caption = "Log"
        self._log_widget: QLogWidget = None

        self._init_widgets()
        self.reload()

    def closeEvent(self, event):
        self._log_widget.close()
        super().closeEvent(event)

    def reload(self):
        pass

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint: disable=unused-argument
        return QSize(0, 50)

    def _init_widgets(self):
        self._log_widget = QLogWidget(self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._log_widget)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)
