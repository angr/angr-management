
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QFileDialog
from PySide2.QtCore import Qt

from angr.sim_type import SimTypeFunction
try:
    from angr.utils.patch_analysis import PatchAnalysis
except ImportError:
    pass


class ArtifactsInference(QDialog):
    def __init__(self, workspace, parent=None):
        super().__init__(parent)

        # initialization
        self.workspace = workspace

        self._artifacts_box: QPlainTextEdit = None
        self._status_label = None
        self._ok_button = None

        self.defs = None
        self.extra_types = None

        self.setWindowTitle('Infer from artifacts')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

        self.show()

        self.initialize()

    def initialize(self):
        file_path, _ = QFileDialog.getOpenFileName(None, "Select an artifact", "",
                                                   "Patches (*.patch);;All files (*)",
                                                   )
        if not file_path:
            self.close()
            return

        with open(file_path, "r") as f:
            data = f.read()

        pa = PatchAnalysis()
        defs, extra_types = pa.analyze_patch(data)

        self.defs = defs
        self.extra_types = extra_types

        txt = [ ]
        txt.append("Definitions:")
        for d_name, d in defs.items():
            txt.append(d_name + " - " + str(d))
        txt.append(" ")
        txt.append("Extra types:")
        for t_name, t in extra_types.items():
            txt.append(t_name + " - " + str(t))

        self._artifacts_box.setPlainText("\n".join(txt))

    def _init_widgets(self):

        artifacts_label = QLabel("Inferred information:")

        artifacts_box = QPlainTextEdit()
        self._artifacts_box = artifacts_box

        layout = QVBoxLayout()
        layout.addWidget(artifacts_label)
        layout.addWidget(artifacts_box)
        self.main_layout.addLayout(layout)

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.clicked.connect(self._on_ok_clicked)
        self._ok_button = ok_button

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(buttons_layout)

    def _on_ok_clicked(self):
        codeview = self.workspace.view_manager.first_view_in_category("pseudocode")
        if codeview is None or codeview._function is None:
            return

        if self.defs:
            for name, proto in self.defs.items():
                if isinstance(proto, SimTypeFunction):
                    codeview._function.name = name
                    codeview._function.prototype = proto
                    codeview.decompile(clear_prototype=False)

        self.close()

    def _on_cancel_clicked(self):
        self.close()
