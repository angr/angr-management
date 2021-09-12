import logging

from PySide2.QtWidgets import QHBoxLayout
from PySide2.QtCore import QSize

from ..widgets.qlog_widget import QLogWidget
from .view import BaseView

_l = logging.getLogger(name=__name__)


class LogView(BaseView):
    """
    Log view displays logging output.
    """

    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('log', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Log'
        self._log_widget: QLogWidget = None

        self._init_widgets()
        self.reload()

    def reload(self):
        pass

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint: disable=unused-argument
        return QSize(0, 50)

    def _init_widgets(self):
        self._log_widget = QLogWidget(self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._log_widget)

        self.setLayout(hlayout)
