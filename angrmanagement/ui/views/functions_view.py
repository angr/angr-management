from PySide2.QtWidgets import QVBoxLayout, QLabel
from PySide2.QtCore import QSize

from .view import BaseView
from ..widgets.qfunction_table import QFunctionTable


class FunctionsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(FunctionsView, self).__init__('functions', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Functions'
        self._function_table = None  # type: QFunctionTable
        self._status_label = None

        self.workspace.instance.cfg.am_subscribe(self.reload)

        self._init_widgets()

        self.width_hint = 100
        self.height_hint = 0
        self.updateGeometry()

        self.function_count = None
        self._displayed_function_count = None

        self.reload()

    #
    # Public methods
    #

    def refresh(self):
        self._function_table.refresh()

    def set_function_count(self, count):
        self.function_count = count
        self._refresh_status_label()

    def set_displayed_function_count(self, count):
        self._displayed_function_count = count
        self._refresh_status_label()

    def reload(self):
        if not self.workspace.instance.cfg.am_none:
            self._function_table.function_manager = self.workspace.instance.kb.functions

    def minimumSizeHint(self, *args, **kwargs):
        return QSize(100, 500)

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
        self._function_table = QFunctionTable(self, self.workspace, selection_callback=self._on_function_selected)
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

    def _refresh_status_label(self):
        if self._status_label is not None:
            function_count = 0 if self.function_count is None else self.function_count
            if self._displayed_function_count is not None:
                self._status_label.setText("%d/%d functions" % (self._displayed_function_count, function_count))
            else:
                self._status_label.setText("%d functions" % function_count)
