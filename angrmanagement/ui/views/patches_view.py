from PySide6.QtWidgets import QVBoxLayout

from angrmanagement.ui.widgets.qpatch_table import QPatchTable

from .view import BaseView


class PatchesView(BaseView):
    """
    View showing all patches.
    """

    def __init__(self, workspace, instance, default_docking_position, *args, **kwargs):
        super().__init__("patches", workspace, instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Patches"
        self._patch_table: QPatchTable

        self._init_widgets()

        # Reload upon creation
        self.reload()

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
