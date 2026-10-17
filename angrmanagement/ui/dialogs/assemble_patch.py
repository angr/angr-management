# FIXME:
# - Add symbol resolve once https://github.com/keystone-engine/keystone/issues/351 is fixed
# - Show symbols in disassembly text
# - Support editing existing patches
# - Handle overlap with existing patches
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from angrmanagement.config import Conf
from angrmanagement.present.dialogs import PatchAssembler

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class AssemblePatchDialog(QDialog):
    """
    Dialog for making a patch from assembly code.
    """

    def __init__(self, address: int, instance: Instance, parent=None) -> None:
        super().__init__(parent)

        self.instance: Instance = instance
        self._patch_addr: int = address
        self._assembler = PatchAssembler(instance, address)
        self._original_bytes: bytes = self._assembler.original_bytes
        self._new_bytes: bytes | None = self._original_bytes
        self._initial_text = self._assembler.initial_text

        self._init_widgets()
        self.setWindowTitle(f"Assemble Patch at {self._patch_addr:#x}")
        self.setMinimumWidth(500)
        self.adjustSize()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self.main_layout = QVBoxLayout()
        font = QFont(Conf.disasm_font)

        grid_layout = QGridLayout()
        grid_layout.addWidget(QLabel("Assembly:", self), 0, 0)
        self._insn_text = QLineEdit(self)
        self._insn_text.setFont(font)
        self._insn_text.setText(self._initial_text)
        self._insn_text.selectAll()
        grid_layout.addWidget(self._insn_text, 0, 1)

        grid_layout.addWidget(QLabel("Bytes:", self), 1, 0)
        self._bytes_text = QLineEdit(self)
        self._bytes_text.setFont(font)
        self._bytes_text.setReadOnly(True)
        grid_layout.addWidget(self._bytes_text, 1, 1)

        self._pad_checkbox = QCheckBox("Pad to original instruction size", self)
        self._pad_checkbox.setChecked(True)
        grid_layout.addWidget(self._pad_checkbox, 2, 1)

        self.main_layout.addLayout(grid_layout)
        self.main_layout.addStretch(1)
        self._status_label = QLabel(self)
        self.main_layout.addWidget(self._status_label)

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

        self.setLayout(self.main_layout)

        if self._assembler.can_assemble:
            self._assemble()
            self._insn_text.textChanged.connect(self._on_text_changed)
            self._pad_checkbox.stateChanged.connect(self._on_checkbox_changed)
        else:
            self._insn_text.setEnabled(False)
            self._bytes_text.setEnabled(False)
            self._pad_checkbox.setEnabled(False)
            self._update_status(self._assembler.unavailable, False)

    def _assemble(self) -> None:
        result = self._assembler.assemble(self._insn_text.text(), self._pad_checkbox.isChecked())
        self._new_bytes = result.new_bytes
        self._update_status(result.message, result.ok)

    def _update_status(self, status_msg, can_press_ok) -> None:
        self._bytes_text.setText(self._new_bytes.hex(" "))
        self._status_label.setText(status_msg)
        self._status_label.setProperty("class", "status_invalid")
        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)
        self._ok_button.setEnabled(can_press_ok)

    #
    # Event handlers
    #

    def _on_text_changed(self, _) -> None:
        self._assemble()

    def _on_checkbox_changed(self, state) -> None:  # pylint: disable=unused-argument
        self._assemble()

    def _on_ok_clicked(self) -> None:
        self._assembler.apply(self._new_bytes or b"")
        self.accept()
