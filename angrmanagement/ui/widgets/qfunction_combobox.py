from typing import TYPE_CHECKING, Optional

from PySide6.QtWidgets import QComboBox

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function, FunctionManager


class QFunctionComboBox(QComboBox):
    def __init__(self, show_all_functions=False, selection_callback=None, parent=None):
        super().__init__(parent)

        self._show_all_functions = show_all_functions
        self._selection_callback = selection_callback

        self._function_manager: Optional[FunctionManager] = None

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
            self.addItem(self._repr_function(function), function)

    def select_function(self, function):
        idx = self.findData(function)
        if idx >= 0:
            self.setCurrentIndex(idx)

    #
    # Event handlers
    #

    def _on_current_index_changed(self):
        idx = self.currentIndex()
        if idx == -1:
            return

        function = self.itemData(idx)

        self._selection_callback(function)

    #
    # Private functions
    #

    @staticmethod
    def _repr_function(func: "Function") -> str:
        demangled_name = func.demangled_name
        if len(demangled_name) > 30:
            demangled_name = demangled_name[:30] + "..."
        return f"{demangled_name} ({func.addr:#x})"
