from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QPushButton, QVBoxLayout

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
        # patch table
        self._patch_table = QPatchTable(self.instance, self)

        #
        # controls
        #
        control_layout = QHBoxLayout()

        # apply patches
        btn_apply_patches = QPushButton("Save patched binary as...")
        btn_apply_patches.clicked.connect(self._on_apply_patches_clicked)
        control_layout.addStretch(0)
        control_layout.addWidget(btn_apply_patches)
        control_layout.setContentsMargins(3, 3, 3, 3)

        layout = QVBoxLayout()
        layout.addLayout(control_layout)
        layout.addWidget(self._patch_table)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    #
    # Events
    #

    def _on_apply_patches_clicked(self):
        # select where the new binary will be stored
        # Open File window
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save the patched binary to...",
            self.instance.project.loader.main_object.binary
            + ".patched",  # FIXME: this will not work if we are loading from an angrdb
            "Any file (*)",
        )

        if file_path:
            b = self.instance.project.kb.patches.apply_patches_to_binary()
            with open(file_path, "wb") as f:
                f.write(b)
