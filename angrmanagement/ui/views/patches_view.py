from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.widgets.qpatch_table import QPatchTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class PatchesView(InstanceView):
    """
    View showing all patches.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("patches", workspace, default_docking_position, instance)

        self.base_caption = "Patches"
        self._patch_table: QPatchTable

        self._init_widgets()

        # Reload upon creation
        self.reload()

    def reload(self) -> None:
        self._patch_table.reload()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._patch_table = QPatchTable(self.instance, self)

        layout = QVBoxLayout()
        layout.addWidget(self._patch_table)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
