from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.present.functions import FunctionsPresenter
from angrmanagement.ui.widgets.qfunction_table import QFunctionTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class FunctionsView(InstanceView):
    """
    View displaying functions in the project.
    """

    presenter: FunctionsPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "functions",
            workspace,
            default_docking_position,
            instance,
            FunctionsPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "Functions"
        self._function_table: QFunctionTable

        # the presenter reloads the table when the CFG changes

        self._init_widgets()

        self.width_hint = 375
        self.height_hint = 0
        self.updateGeometry()

        self.reload()

    #
    # Public methods
    #

    def reset_cache_and_refresh(self) -> None:
        self._function_table._table_view._model.clear_data_cache()
        self.refresh()

    def refresh(self) -> None:
        self._function_table.refresh()

    def reload(self) -> None:
        self.presenter.reload()

    def closeEvent(self, event) -> None:
        self.presenter.close()
        super().closeEvent(event)

    def subscribe_func_select(self, callback) -> None:
        """
        Appends the provided function to the list of callbacks to be called when a function is selected in the
        functions table. The callback's only parameter is the `angr.knowledge_plugins.functions.function.Function`
        :param callback: The callback function to call, which must accept **kwargs
        """
        self._function_table.subscribe_func_select(callback)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # the presenter tells the workspace when a function is chosen
        self._function_table = QFunctionTable(self, self.instance, presenter=self.presenter)

        vlayout = QVBoxLayout()
        vlayout.addWidget(self._function_table)
        vlayout.setSpacing(0)
        vlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vlayout)

    def _on_function_selected(self, func) -> None:
        """
        A new function is on selection right now. Update the disassembly view that is currently at front.

        :param function:
        :return:
        """
        self.workspace.on_function_selected(func=func)
