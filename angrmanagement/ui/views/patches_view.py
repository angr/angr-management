
from PySide2.QtWidgets import QVBoxLayout

from .view import BaseView
from ..widgets.qpatch_table import QPatchTable


class PatchesView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('patches', workspace, default_docking_position, *args, **kwargs)

        self.caption = "Patches"
        self._patch_table = None  # type: QPatchTable

        self._init_widgets()

    def reload(self):
        self._patch_table.reload()

    #
    # Private methods
    #

    def _init_widgets(self):

        self._patch_table = QPatchTable(self.workspace.instance, self)

        layout = QVBoxLayout(self)
        layout.addWidget(self._patch_table)
        self.setLayout(layout)
