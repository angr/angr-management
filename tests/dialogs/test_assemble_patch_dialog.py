"""
Test cases for AssemblePatchDialog.
"""

from __future__ import annotations

# pylint: disable=no-self-use
import unittest
from unittest.mock import MagicMock, patch

from angr import Block
from archinfo import arch_from_id
from common import AngrManagementTestCase  # pylint: disable=import-error
from PySide6.QtWidgets import QApplication

from angrmanagement.ui.dialogs.assemble_patch import AssemblePatchDialog


def _make_instance(insn_bytes, arch_id):
    """Build a mock Instance with a real angr Block and arch."""
    arch = arch_from_id(arch_id)
    block = Block(0x1000, arch=arch, byte_string=insn_bytes)

    instance = MagicMock()
    instance.project.factory.block.return_value = block
    instance.project.arch = arch
    return instance


class AssemblePatchDialogTestCase(AngrManagementTestCase):
    """Base class for AssemblePatchDialog tests with shared helpers."""

    def _make_dialog(self, instance) -> AssemblePatchDialog:
        """Construct an AssemblePatchDialog and schedule cleanup."""
        dialog = AssemblePatchDialog(0x1000, instance, parent=self.main)
        self.addCleanup(dialog.close)
        self.addCleanup(dialog.deleteLater)
        return dialog


class TestAssemblePatchDialogInit(AssemblePatchDialogTestCase):
    """Test AssemblePatchDialog initialization."""

    def test_initial_text_without_operands(self):
        """Test assembly text field populated with mnemonic only when no operands."""
        instance = _make_instance(b"\x90", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._insn_text.text() == "nop"

    def test_initial_text_with_operands(self):
        """Test assembly text field populated with mnemonic and operands."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._insn_text.text() == "xor ebp, ebp"

    def test_bytes_field_populated(self):
        """Test bytes field shows assembled bytes on init."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert len(dialog._bytes_text.text()) > 0
        assert dialog._bytes_text.text() == "31 ed"

    def test_bytes_field_readonly(self):
        """Test bytes field is read-only."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._bytes_text.isReadOnly()

    def test_pad_checkbox_checked_by_default(self):
        """Test pad checkbox is checked by default."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._pad_checkbox.isChecked()

    def test_original_bytes_stored(self):
        """Test original bytes are stored from instruction."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._original_bytes == b"\x31\xed"

    def test_ok_enabled_when_valid_assembly(self):
        """Test OK button enabled after successful initial assembly."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._ok_button.isEnabled()


class TestAssemblePatchDialogAssembly(AssemblePatchDialogTestCase):
    """Test assembly and text change behavior."""

    def test_text_change_triggers_reassembly(self):
        """Test changing text reassembles instruction."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        assert dialog._new_bytes == dialog._original_bytes

        dialog._insn_text.setText("nop")
        QApplication.processEvents()

        assert dialog._new_bytes is not None
        assert dialog._new_bytes != dialog._original_bytes
        assert dialog._bytes_text.text() == "90 90"

    def test_empty_text_produces_nop_padding(self):
        """Test empty assembly text gets NOP-padded when pad checkbox checked."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._insn_text.setText("")
        QApplication.processEvents()

        assert dialog._new_bytes == b"\x90\x90"
        assert dialog._bytes_text.text() == "90 90"
        assert dialog._ok_button.isEnabled()

    def test_empty_text_no_padding_produces_empty_bytes(self):
        """Test empty assembly text without padding produces empty bytes."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._pad_checkbox.setChecked(False)
        dialog._insn_text.setText("")
        QApplication.processEvents()

        assert dialog._new_bytes == b""
        assert dialog._bytes_text.text() == ""
        assert not dialog._ok_button.isEnabled()

    def test_invalid_assembly_shows_error(self):
        """Test invalid assembly shows error status."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._insn_text.setText("not_a_real_instruction xyz")
        QApplication.processEvents()

        assert dialog._new_bytes == b""
        assert dialog._bytes_text.text() == ""
        assert "Error:" in dialog._status_label.text()
        assert not dialog._ok_button.isEnabled()

    def test_nop_padding_when_shorter(self):
        """Test shorter instruction gets NOP-padded when checkbox checked."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._insn_text.setText("push rax")
        QApplication.processEvents()

        assert dialog._new_bytes is not None
        assert len(dialog._new_bytes) == 2
        assert dialog._new_bytes == b"\x50\x90"
        assert dialog._bytes_text.text() == "50 90"

    def test_no_padding_when_checkbox_unchecked(self):
        """Test shorter instruction not padded when checkbox unchecked."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._pad_checkbox.setChecked(False)
        dialog._insn_text.setText("nop")
        QApplication.processEvents()

        assert dialog._new_bytes is not None
        assert len(dialog._new_bytes) == 1
        assert dialog._new_bytes == b"\x90"
        assert dialog._bytes_text.text() == "90"

    def test_longer_instruction_shows_warning(self):
        """Test instruction longer than original shows warning."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._insn_text.setText("mov rax, 0x1234567890abcdef")
        QApplication.processEvents()

        assert "Warning:" in dialog._status_label.text()
        assert "exceeds" in dialog._status_label.text()
        assert dialog._ok_button.isEnabled()

    def test_checkbox_toggle_triggers_reassembly(self):
        """Test toggling pad checkbox triggers reassembly."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        dialog = self._make_dialog(instance)

        dialog._insn_text.setText("nop")
        QApplication.processEvents()
        padded_bytes = dialog._new_bytes

        dialog._pad_checkbox.setChecked(False)
        QApplication.processEvents()
        unpadded_bytes = dialog._new_bytes

        assert padded_bytes is not None
        assert unpadded_bytes is not None
        assert len(padded_bytes) > len(unpadded_bytes)


class TestAssemblePatchDialogNoKeystone(AssemblePatchDialogTestCase):
    """Test behavior when keystone is not available."""

    def test_widgets_disabled_without_keystone(self):
        """Test all input widgets disabled when keystone not available."""
        instance = _make_instance(b"\x31\xed", "x86_64")
        with patch("angrmanagement.ui.dialogs.assemble_patch.keystone", None):
            dialog = self._make_dialog(instance)

            assert not dialog._insn_text.isEnabled()
            assert not dialog._bytes_text.isEnabled()
            assert not dialog._pad_checkbox.isEnabled()
            assert dialog._status_label.text() == "Keystone not installed"
            assert not dialog._ok_button.isEnabled()


if __name__ == "__main__":
    unittest.main()
