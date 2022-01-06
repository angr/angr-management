from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QDialogButtonBox


class LabelNameBox(QLineEdit):
    """
    A QLineEdit that sanitizes label names.
    """

    def __init__(self, textchanged_callback, parent=None):
        super().__init__(parent)

        self.textChanged.connect(textchanged_callback)

    @property
    def label(self):
        text = self.text()
        if self._is_valid_label_name(text):
            return text.strip()
        return None

    def _is_valid_label_name(self, input_):  # pylint: disable=no-self-use
        return input_ and not ' ' in input_.strip()


class RenameLabel(QDialog):
    """
    Dialog to rename labels.
    """

    def __init__(self, disasm_view, label_addr, parent=None):
        super().__init__(parent)

        # initialization
        self._disasm_view = disasm_view
        self._label_addr = label_addr

        self._name_box: LabelNameBox = None
        self._status_label = None
        self._ok_button: QPushButton = None

        self.setWindowTitle('Rename Label')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):

        # name label

        name_label = QLabel(self)
        name_label.setText('New name')

        name_box = LabelNameBox(self._on_name_changed, self)
        if self._label_addr in self._disasm_view.disasm.kb.labels:
            name_box.setText(self._disasm_view.disasm.kb.labels[self._label_addr])
            name_box.selectAll()
        self._name_box = name_box

        label_layout = QHBoxLayout()
        label_layout.addWidget(name_label)
        label_layout.addWidget(name_box)
        self.main_layout.addLayout(label_layout)

        # status label
        status_label = QLabel(self)
        self.main_layout.addWidget(status_label)
        self._status_label = status_label

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self._ok_button = buttons.button(QDialogButtonBox.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_name_changed(self, new_text): # pylint: disable=unused-argument

        if self._name_box is None:
            # initialization is not done yet
            return

        if self._name_box.label is None:
            # the label name is invalid

            self._status_label.setText('Invalid')
            self._status_label.setProperty('class', 'status_invalid')
            self._ok_button.setEnabled(False)
        else:
            self._status_label.setText('Valid')
            self._status_label.setProperty('class', 'status_valid')
            self._ok_button.setEnabled(True)

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self):
        label = self._name_box.label
        if label is not None:
            self._disasm_view.rename_label(self._label_addr, label)
            self.close()
