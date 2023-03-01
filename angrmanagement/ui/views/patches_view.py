from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.widgets.qpatch_table import QPatchTable

from .view import BaseView


class PatchesView(BaseView):
    def __init__(self, instance, default_docking_position, *args, **kwargs):
        super().__init__("patches", instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Patches"
        self._patch_table: QPatchTable

        self._init_widgets()

    def reload(self):
        self._patch_table.reload()

    #
    # Private methods
    #

    def _init_widgets(self):
        self._patch_table = QPatchTable(self.instance, self)

        layout = QVBoxLayout()
        layout.addWidget(self._patch_table)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
