from __future__ import annotations

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout


class LabelNameBox(QLineEdit):
    """
    A QLineEdit that sanitizes label names.
    """

    def __init__(self, textchanged_callback, parent=None) -> None:
        super().__init__(parent)

        self.textChanged.connect(textchanged_callback)

    @property
    def label(self):
        text = self.text()
        if not text or self._is_valid_label_name(text):
            return text.strip()
        return None

    def _is_valid_label_name(self, input_):  # pylint: disable=no-self-use
        return input_ and " " not in input_.strip()


class RenameLabel(QDialog):
    """
    Dialog to rename labels.
    """

    def __init__(self, disasm_view, label_addr, full_refresh: bool = False, parent=None) -> None:
        super().__init__(parent)

        # initialization
        self._disasm_view = disasm_view
        self._label_addr = label_addr
        self._full_refresh = full_refresh
        self._label_type: str = None

        self._name_box: LabelNameBox = None
        self._status_label = None
        self._ok_button: QPushButton = None

        self.setWindowTitle(f"Rename Label at {self._label_addr:#08x}")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # name label

        name_label = QLabel(self)
        name_label.setText("New name")

        name_box = LabelNameBox(self._on_name_changed, self)
        text = ""
        if self._disasm_view.disasm.kb.functions.contains_addr(self._label_addr):
            self._label_type = "function"
            text = self._disasm_view.disasm.kb.functions.get_by_addr(self._label_addr).name
        else:
            self._label_type = "label"
            if self._label_addr in self._disasm_view.disasm.kb.labels:
                text = self._disasm_view.disasm.kb.labels[self._label_addr]

        if text:
            name_box.setText(text)
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
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_name_changed(self, new_text) -> None:  # pylint: disable=unused-argument
        if self._name_box is None:
            # initialization is not done yet
            return

        if self._name_box.label is None:
            # the label name is invalid

            self._status_label.setText("Invalid")
            self._status_label.setProperty("class", "status_invalid")
            self._ok_button.setEnabled(False)
        else:
            self._status_label.setText("Valid")
            self._status_label.setProperty("class", "status_valid")
            self._ok_button.setEnabled(True)

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self) -> None:
        label = self._name_box.label
        if label is not None:
            self._disasm_view.rename_label(
                self._label_addr, label, is_func=self._label_type == "function", full_refresh=self._full_refresh
            )
            self.close()
