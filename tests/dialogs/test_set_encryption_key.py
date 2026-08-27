"""
Test cases for SetEncryptionKeyDialog.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import base64
import unittest

from common import create_qapp  # pylint: disable=import-error

from angrmanagement.ui.dialogs.set_encryption_key import SetEncryptionKeyDialog, key_to_hex

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

    def test_auto_detect_hex(self) -> None:
        assert self.dialog._get_enckey(key_to_hex(KEY)) == KEY
        assert self.dialog._get_enckey(KEY.hex()) == KEY
        assert self.dialog._get_enckey("0x" + KEY.hex()) == KEY
        assert self.dialog._get_enckey(KEY.hex().upper()) == KEY
        assert self.dialog._get_enckey("de:ad-be ef") == b"\xde\xad\xbe\xef"

    def test_hex_wins_over_base64_for_hex_shaped_text(self) -> None:
        # KEY.hex() is 68 characters, all of which are in the base64 alphabet, and 68 % 4 == 0, so
        # base64 would happily decode it into 51 completely different bytes
        assert base64.b64decode(KEY.hex(), validate=True) != KEY
        assert self.dialog._get_enckey(KEY.hex()) == KEY

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

    def test_forced_hex(self) -> None:
        self.dialog._hex_radio.setChecked(True)
        assert self.dialog._get_enckey(key_to_hex(KEY)) == KEY
        # an odd number of digits is not a whole number of bytes
        assert self.dialog._get_enckey("abc") is None
        # no other format is attempted
        assert self.dialog._get_enckey("infected!") is None
        assert self.dialog._get_enckey(base64.b64encode(KEY).decode("ascii")) is None

    def test_forced_base64(self) -> None:
        self.dialog._base64_radio.setChecked(True)
        assert self.dialog._get_enckey(base64.b64encode(KEY).decode("ascii")) == KEY
        # hex is not attempted even though this text is hex-shaped
        assert self.dialog._get_enckey(KEY.hex()) == base64.b64decode(KEY.hex(), validate=True)
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
        # hex is what the dialog hands out, so it must be what it takes back
        dialog = SetEncryptionKeyDialog(initial_text=key_to_hex(KEY))
        try:
            assert dialog._ok_button.isEnabled()
            assert dialog._status_label.text() == "Valid"
            dialog._on_ok_clicked()
            assert dialog.result == KEY
        finally:
            dialog.close()

    def test_hex_preview_round_trips(self) -> None:
        self.dialog._enckey_box.setText(repr(KEY))
        assert self.dialog._key_preview_bytes.text() == "Key in hex: " + key_to_hex(KEY)
        assert self.dialog._get_enckey(key_to_hex(KEY)) == KEY


if __name__ == "__main__":
    unittest.main(argv=[__file__])
