from __future__ import annotations

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QVBoxLayout

from angrmanagement.ui.widgets import QAddressInput


class JumpTo(QDialog):
    """
    Dialog to jump to an address.
    """

    def __init__(self, disasm_view, parent=None) -> None:
        super().__init__(parent)

        # initialization
        self._disasm_view = disasm_view

        self._address_box = None
        self._status_label = None
        self._ok_button = None

        self.setWindowTitle("Jump to address")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

        self.show()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        # address label

        address_label = QLabel(self)
        address_label.setText("Address")

        address = QAddressInput(self._on_address_changed, self._disasm_view.instance, parent=self)
        self._address_box = address

        address_layout = QHBoxLayout()
        address_layout.addWidget(address_label)
        address_layout.addWidget(address)
        self.main_layout.addLayout(address_layout)

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

    def _on_address_changed(self, new_text) -> None:  # pylint: disable=unused-argument
        if self._address_box.target is None:
            # the address is invalid

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
        addr = self._address_box.target
        if addr is not None:
            r = self._disasm_view.jump_to(addr)
            if r:
                self.close()
