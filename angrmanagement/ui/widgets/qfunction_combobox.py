from PySide2.QtWidgets import QComboBox, QHBoxLayout

from angr.knowledge_plugins import FunctionManager


class QFunctionComboBox(QComboBox):
    def __init__(self, show_all_functions=False, selection_callback=None, parent=None):
        super(QFunctionComboBox, self).__init__(parent)

        self._show_all_functions = show_all_functions
        self._selection_callback = selection_callback

        self._function_manager = None  # type: FunctionManager

        self.currentIndexChanged.connect(self._on_current_index_changed)

    #
    # Properties
    #

    @property
    def functions(self):
        return self._function_manager

    @functions.setter
    def functions(self, v):
        if v is not self._function_manager:
            self._function_manager = v
            self.reload()

    #
    # Public methods
    #

    def reload(self):

        if self._function_manager is None:
            return

        self.clear()

        if self._show_all_functions:
            self.addItem("All functions", "all")

        for function in self._function_manager.values():
            self.addItem(repr(function), function)

    #
    # Event handlers
    #

    def _on_current_index_changed(self):

        idx = self.currentIndex()
        if idx == -1:
            return

        function = self.itemData(idx)

        self._selection_callback(function)
