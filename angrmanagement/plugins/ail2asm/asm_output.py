from PySide2.QtGui import Qt
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit, QDialogButtonBox


class AsmOutput(QDialog):
    """
    Displays generated assembly code
    """

    def __init__(self, s: str, parent=None):
        super().__init__(parent)

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self._edit: QPlainTextEdit = None

        self.setWindowTitle('Assembly code output')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

        self._edit.setPlainText(s)

        self.show()

    #
    # Private methods
    #

    def _init_widgets(self):

        # Assembly label

        asm_label = QLabel(self)
        asm_label.setText('Assembly code')

        edit = QPlainTextEdit()
        edit.setMinimumWidth(600)
        edit.setMinimumHeight(400)
        self._edit = edit

        edit_layout = QHBoxLayout()
        edit_layout.addWidget(asm_label)
        edit_layout.addWidget(edit)
        self.main_layout.addLayout(edit_layout)

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.close)
        self.main_layout.addWidget(buttons)
