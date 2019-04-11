from PySide2.QtWidgets import QVBoxLayout, QLabel
from PySide2.QtCore import QSize

from .view import BaseView
from ..widgets.qfunction_table import QFunctionTable


class FunctionsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(FunctionsView, self).__init__('functions', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Functions'
        self._function_table = None  # type: QFunctionTable
        self._status_label = None

        self.backcolor_callback = None

        self._init_widgets()

        self.width_hint = 100
        self.height_hint = 0
        self.updateGeometry()

    #
    # Public methods
    #

    def get_function_backcolor(self, func):
        if self.backcolor_callback:
            return self.backcolor_callback(func)
        else:
            return 255, 255, 255

    def set_function_count(self, count):
        if self._status_label is not None:
            self._status_label.setText("%d functions" % count)

    def reload(self):
        self._function_table.function_manager = self.workspace.instance.cfg.functions

    def minimumSizeHint(self, *args, **kwargs):
        return QSize(100, 0)

    def subscribe_func_select(self, callback):
        """
        Appends the provided function to the list of callbacks to be called when a function is selected in the
        functions table. The callback's only parameter is the `angr.knowledge_plugins.functions.function.Function`
        :param callback: The callback function to call, which must accept **kwargs
        """
        self._function_table.subscribe_func_select(callback)

    #
    # Private methods
    #

    def _init_widgets(self):

        self._function_table = QFunctionTable(self, selection_callback=self._on_function_selected)
        self._status_label = QLabel()

        vlayout = QVBoxLayout()
        vlayout.addWidget(self._function_table)
        vlayout.addWidget(self._status_label)

        self.setLayout(vlayout)

    def _on_function_selected(self, func):
        """
        A new function is on selection right now. Update the disassembly view that is currently at front.

        :param function:
        :return:
        """
        self.workspace.on_function_selected(func=func)

