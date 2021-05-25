from PySide2.QtWidgets import QHBoxLayout, QVBoxLayout, QLabel
from PySide2.QtCore import QSize

from ..widgets.qinsight_generic import QInsightGeneric
from .view import BaseView


class InsightsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('insights', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Insights'

        self._init_widgets()

    def reload(self):
        self._init_widgets()

    def sizeHint(self):
        return QSize(400, 800)

    #
    # Event handlers
    #


    #
    # Private methods
    #

    def _init_widgets(self):

        if self.workspace.instance.project.am_none:
            return

        layout = QVBoxLayout()

        for name, insight in self.workspace.instance.kb.insights.items():
            control = QInsightGeneric(name, insight)
            layout.addWidget(control)

        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
