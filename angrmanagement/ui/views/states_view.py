from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QHBoxLayout

from angrmanagement.ui.widgets.qstate_table import QStateTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class StatesView(InstanceView):
    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("states", workspace, default_docking_position, instance)

        self.base_caption = "States"
        self._state_table: QStateTable

        self._init_widgets()

    def reload(self) -> None:
        self._state_table.state_manager = self.instance.states

    def closeEvent(self, event) -> None:
        """
        Close children before exiting
        """
        self._state_table.close()

    def sizeHint(self):
        return QSize(400, 800)

    def _init_widgets(self) -> None:
        self._state_table = QStateTable(self.workspace, self.instance, self, selection_callback=self._on_state_selected)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._state_table)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

    def _on_state_selected(self, state) -> None:
        """
        A new function is on selection right now. Update the disassembly view that is currently at front.

        :param function:
        :return:
        """
