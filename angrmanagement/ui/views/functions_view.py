from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.widgets.qfunction_table import QFunctionTable

from .view import BaseView


class FunctionsView(BaseView):
    """
    View displaying functions in the project.
    """

    def __init__(self, instance, default_docking_position, *args, **kwargs):
        super().__init__("functions", instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Functions"
        self._function_table: QFunctionTable

        self.instance.cfg.am_subscribe(self.reload)

        self._init_widgets()

        self.width_hint = 300
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

    def set_displayed_function_count(self, count):
        self._displayed_function_count = count

    def reload(self):
        if not self.instance.cfg.am_none:
            self._function_table.function_manager = self.instance.kb.functions

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
        self._function_table = QFunctionTable(self, self.instance, selection_callback=self._on_function_selected)

        vlayout = QVBoxLayout()
        vlayout.addWidget(self._function_table)
        vlayout.setSpacing(0)
        vlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vlayout)

    def _on_function_selected(self, func):
        """
        A new function is on selection right now. Update the disassembly view that is currently at front.

        :param function:
        :return:
        """
        self.instance.on_function_selected(func=func)
