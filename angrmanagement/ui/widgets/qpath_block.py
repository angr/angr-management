
from PySide.QtGui import QFrame, QHBoxLayout, QPushButton

class QPathBlock(QFrame):
    def __init__(self, name, path, is_selected, parent=None):
        super(QPathBlock, self).__init__(parent)

        self.name = name
        self.path = path
        self.is_selected = is_selected

        self._init_widgets()

    def _init_widgets(self):

        # the path button

        path_button = QPushButton()
        path_button.setText('Path@%#x' % self.path.addr)
        path_button.released.connect(self._on_path_button_released)

        # the disasm button

        disasm_button = QPushButton()
        disasm_button.setText('Disasm')
        disasm_button.released.connect(self._on_disasm_button_released)

        layout = QHBoxLayout()
        layout.addWidget(path_button)
        layout.addWidget(disasm_button)

        self.setLayout(layout)

    #
    # Events
    #

    def _on_path_button_released(self):
        self.is_selected = True

    def _on_disasm_button_released(self):
        pass
