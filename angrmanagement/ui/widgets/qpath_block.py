
from PySide.QtGui import QFrame, QHBoxLayout, QVBoxLayout, QPushButton, QLabel

class QPathBlock(QFrame):
    def __init__(self, name, path, is_selected, symexec_view, parent=None):
        super(QPathBlock, self).__init__(parent)

        self.symexec_view = symexec_view
        self._workspace = self.symexec_view.workspace

        self.name = name
        self.path = path
        self.selected = is_selected

        self._init_widgets()

    def _init_widgets(self):

        # label
        label = QLabel()
        label.setText('%#x' % self.path.addr)

        # the select button

        path_button = QPushButton()
        path_button.setText('Select')
        path_button.released.connect(self._on_path_button_released)

        # the disasm button

        disasm_button = QPushButton()
        disasm_button.setText('Disasm')
        disasm_button.released.connect(self._on_disasm_button_released)

        sublayout = QHBoxLayout()
        sublayout.addWidget(path_button)
        sublayout.addWidget(disasm_button)

        layout = QVBoxLayout()
        layout.addWidget(label)
        layout.addLayout(sublayout)

        self.setLayout(layout)

    #
    # Events
    #

    def _on_path_button_released(self):
        self.selected = True
        self.symexec_view.view_path(self.path)

    def _on_disasm_button_released(self):
        disasm_view = self._workspace.views_by_category['disassembly'][0]
        disasm_view.jump_to(self.path.addr)

        self._workspace.raise_view(disasm_view)
