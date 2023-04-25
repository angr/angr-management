from typing import Optional

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout


class NameLineEdit(QLineEdit):
    """
    Simple line edit with simple identifier validation.
    """

    def __init__(self, textchanged_callback, parent=None):
        super().__init__(parent)

        self.textChanged.connect(textchanged_callback)

    @property
    def name(self):
        text = self.text()
        if self._is_valid_node_name(text):
            return text.strip()
        return None

    @staticmethod
    def _is_valid_node_name(name):
        return name and " " not in name.strip()


class RenameDialog(QDialog):
    """
    A generic dialog box for renaming something.

    If the user enters a valid name and clicks 'OK', the `result` property will
    contain the resulting string. If a user clicks 'Cancel', the `result`
    property will remain `None`.
    """

    def __init__(self, window_title: str = "Rename", initial_text: str = "", parent=None):
        super().__init__(parent)
        self._initial_text: str = initial_text
        self._name_box: NameLineEdit = None
        self._status_label: QLabel = None
        self._ok_button: QPushButton = None
        self.main_layout: QVBoxLayout = QVBoxLayout()
        self.result: Optional[str] = None
        self._init_widgets()
        self.setLayout(self.main_layout)
        self.setWindowTitle(window_title)

    #
    # Private methods
    #

    def _init_widgets(self):
        name_label = QLabel(self)
        name_label.setText("New name")
        name_box = NameLineEdit(self._on_name_changed, self)
        name_box.setText(self._initial_text)
        name_box.selectAll()
        self._name_box = name_box

        label_layout = QHBoxLayout()
        label_layout.addWidget(name_label)
        label_layout.addWidget(name_box)
        self.main_layout.addLayout(label_layout)

        status_label = QLabel(self)
        self.main_layout.addWidget(status_label)
        self._status_label = status_label

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

    def _on_name_changed(self, new_text):  # pylint:disable=unused-argument
        if self._name_box is None:
            # initialization is not done yet
            return

        if self._name_box.name is None:
            # the variable name is invalid
            self._status_label.setText("Invalid")
            self._status_label.setProperty("class", "status_invalid")
            self._ok_button.setEnabled(False)
        else:
            self._status_label.setText("Valid")
            self._status_label.setProperty("class", "status_valid")
            self._ok_button.setEnabled(True)

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self):
        node_name = self._name_box.name
        if node_name is not None:
            self.result = node_name
            self.close()
