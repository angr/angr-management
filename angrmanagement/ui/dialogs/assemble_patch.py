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

try:
    import keystone
except ImportError:
    keystone = None

from angr.knowledge_plugins.patches import Patch
from archinfo import ArchError

from angrmanagement.config import Conf

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

        block = self.instance.project.factory.block(self._patch_addr)
        insn = block.disassembly.insns[0]

        self._original_bytes: bytes = block.bytes[: insn.size]
        self._new_bytes: bytes | None = self._original_bytes
        self._initial_text = insn.mnemonic
        if insn.op_str:
            self._initial_text += " " + insn.op_str

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

        can_assemble = False
        status_msg = ""
        if keystone:
            try:
                ks = self.instance.project.arch.keystone
                can_assemble = ks is not None
            except ArchError as e:
                status_msg = str(e)
        else:
            status_msg = "Keystone not installed"

        if can_assemble:
            self._assemble()
            self._insn_text.textChanged.connect(self._on_text_changed)
            self._pad_checkbox.stateChanged.connect(self._on_checkbox_changed)
        else:
            self._insn_text.setEnabled(False)
            self._bytes_text.setEnabled(False)
            self._pad_checkbox.setEnabled(False)
            self._update_status(status_msg, False)

    def _assemble(self) -> None:
        success = False
        status_msg = ""

        try:
            ks = self.instance.project.arch.keystone

            text = self._insn_text.text()
            if len(text) > 0:
                self._new_bytes = ks.asm(self._insn_text.text(), self._patch_addr, as_bytes=True)[0] or b""
            else:
                self._new_bytes = b""

            # Pad to original instruction length
            byte_length_delta = len(self._original_bytes) - len(self._new_bytes)
            if byte_length_delta > 0:
                if self._pad_checkbox.isChecked():
                    nop_instruction_bytes = self.instance.project.arch.nop_instruction
                    self._new_bytes += (byte_length_delta // len(nop_instruction_bytes)) * nop_instruction_bytes
                    byte_length_delta = len(self._original_bytes) - len(self._new_bytes)
                    if byte_length_delta:
                        status_msg = "Warning: Unable to completely pad remainder"
            elif byte_length_delta < 0:
                status_msg = "Warning: Patch exceeds original instruction length"

            success = True
        except keystone.KsError as ks_error:
            self._new_bytes = b""
            status_msg = "Error: " + ks_error.message

        self._update_status(status_msg, success and len(self._new_bytes) > 0)

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

    def _on_text_changed(self, new_text) -> None:  # pylint: disable=unused-argument
        self._assemble()

    def _on_checkbox_changed(self, state) -> None:  # pylint: disable=unused-argument
        self._assemble()

    def _on_ok_clicked(self) -> None:
        if self._new_bytes != self._original_bytes:
            pm = self.instance.project.kb.patches

            # XXX: Currently patch manager stores patches by address, so remove any existing patch at this addr
            existing_patch = pm.get_patch(self._patch_addr)
            if existing_patch:
                self.instance.patches.remove_patch(existing_patch.addr)
                self.instance.patches.am_event(removed={existing_patch})

            patch = Patch(self._patch_addr, self._new_bytes)
            pm.add_patch_obj(patch)
            self.instance.patches.am_event(added={patch})

        self.accept()
