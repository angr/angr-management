from PySide6.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout


class InputPromptDialog(QDialog):
    """
    A generic dialog to prompt for text input.
    """

    def __init__(self, window_title: str, prompt_text: str, initial_input_text: str = "", parent=None):
        super().__init__(parent)
        self.prompt_text: str = prompt_text
        self.initial_input_text: str = initial_input_text
        self.input_edt: QLineEdit = None
        self.result = None

        self.setWindowTitle(window_title)
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):
        prompt_lbl = QLabel(self)
        prompt_lbl.setText(self.prompt_text)

        input_edt = QLineEdit(parent=self)
        input_edt.setText(self.initial_input_text)
        input_edt.selectAll()
        self.input_edt = input_edt

        prompt_input_lyt = QHBoxLayout()
        prompt_input_lyt.addWidget(prompt_lbl)
        prompt_input_lyt.addWidget(input_edt)
        self.main_layout.addLayout(prompt_input_lyt)

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        buttons_lyt = QHBoxLayout()
        buttons_lyt.addWidget(buttons)
        self.main_layout.addLayout(buttons_lyt)

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        self.result = self.input_edt.text()
        self.close()
