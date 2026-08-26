"""
Test cases for SetEncryptionKeyDialog.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import base64
import unittest

from common import create_qapp  # pylint: disable=import-error

from angrmanagement.ui.dialogs.set_encryption_key import SetEncryptionKeyDialog

KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class TestSetEncryptionKeyDialog(unittest.TestCase):
    """Test key parsing and the OK button state of SetEncryptionKeyDialog."""

    def setUp(self) -> None:
        create_qapp()
        self.dialog = SetEncryptionKeyDialog()

    def tearDown(self) -> None:
        self.dialog.close()

    #
    # Auto-detection
    #

    def test_auto_detect_base64(self) -> None:
        assert self.dialog._get_enckey(base64.b64encode(KEY).decode("ascii")) == KEY

    def test_auto_detect_byte_string(self) -> None:
        assert self.dialog._get_enckey(repr(KEY)) == KEY
        assert self.dialog._get_enckey(r"b'\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00'") == KEY
        assert self.dialog._get_enckey(r'b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"') == KEY

    def test_auto_detect_bare_escapes(self) -> None:
        assert self.dialog._get_enckey(r"\x41\x42") == b"AB"

    def test_auto_detect_ascii(self) -> None:
        # "infected!" is not valid base64 and not a byte string, so it falls through to ASCII
        assert self.dialog._get_enckey("infected!") == b"infected!"

    def test_empty_key_is_invalid(self) -> None:
        assert self.dialog._get_enckey("") is None

    #
    # Forced formats
    #

    def test_forced_base64(self) -> None:
        self.dialog._base64_radio.setChecked(True)
        assert self.dialog._get_enckey(base64.b64encode(KEY).decode("ascii")) == KEY
        # a byte string is not valid base64, and no other format is attempted
        assert self.dialog._get_enckey(repr(KEY)) is None

    def test_forced_byte_string(self) -> None:
        self.dialog._bytestring_radio.setChecked(True)
        assert self.dialog._get_enckey(repr(KEY)) == KEY
        # base64 is not attempted, so this is read as bare escaped content
        assert self.dialog._get_enckey("asdf") == b"asdf"
        assert self.dialog._get_enckey(r"\xzz") is None

    def test_forced_ascii(self) -> None:
        self.dialog._ascii_radio.setChecked(True)
        # base64 is not attempted even though this decodes as base64
        assert self.dialog._get_enckey("asdfasdf") == b"asdfasdf"
        assert self.dialog._get_enckey("☃") is None

    def test_no_arbitrary_code_execution(self) -> None:
        """The byte-string parser must not evaluate arbitrary expressions."""
        self.dialog._bytestring_radio.setChecked(True)
        assert self.dialog._get_enckey('" + __import__("os").getcwd().encode() + b"') is None

    #
    # Widget state
    #

    def test_ok_button_follows_key_validity(self) -> None:
        assert not self.dialog._ok_button.isEnabled()

        self.dialog._enckey_box.setText(repr(KEY))
        assert self.dialog._ok_button.isEnabled()
        assert self.dialog._status_label.text() == "Valid"

        self.dialog._enckey_box.setText("")
        assert not self.dialog._ok_button.isEnabled()
        assert self.dialog._status_label.text() == "Invalid"

    def test_result_is_set_on_ok(self) -> None:
        assert self.dialog.result is None
        self.dialog._enckey_box.setText(repr(KEY))
        self.dialog._on_ok_clicked()
        assert self.dialog.result == KEY

    def test_initial_text_is_validated(self) -> None:
        dialog = SetEncryptionKeyDialog(initial_text=repr(KEY))
        try:
            assert dialog._ok_button.isEnabled()
            dialog._on_ok_clicked()
            assert dialog.result == KEY
        finally:
            dialog.close()


if __name__ == "__main__":
    unittest.main(argv=[__file__])
