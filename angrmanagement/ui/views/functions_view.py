
from PySide.QtGui import QHBoxLayout
from PySide.QtCore import QSize

from .view import BaseView
from ..widgets.qfunction_table import QFunctionTable


class FunctionsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(FunctionsView, self).__init__('functions', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Functions'
        self._function_table = None

        self._init_widgets()

    def reload(self):
        self._function_table.function_manager = self.workspace.instance.cfg.functions

    def sizeHint(self):
        return QSize(200, 0)

    def _init_widgets(self):

        self._function_table = QFunctionTable(self, selection_callback=self._on_function_selected)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._function_table)

        self.setLayout(hlayout)

    def _on_function_selected(self, function):
        """
        A new function is on selection right now. Update the disassembly view that is currently at front.

        :param function:
        :return:
        """

        self.workspace.views_by_category['disassembly'][0].display_function(function)
