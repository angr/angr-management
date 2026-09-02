"""
Test cases for the LoadBinary dialog.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import os
import unittest

import cle
from common import create_qapp, test_location  # pylint: disable=import-error

from angrmanagement.ui.dialogs.load_binary import LoadBinary

BINARY_PATH = os.path.join(test_location, "x86_64", "true")


def make_dialog(partial_ld: cle.Loader) -> LoadBinary:
    """Build a LoadBinary dialog with the arguments LoadBinaryJob passes."""
    original_main_object = partial_ld.original_main_object
    return LoadBinary(
        partial_ld,
        suggested_backend=partial_ld.main_object.__class__,
        suggested_os_name=partial_ld.main_object.os,
        suggested_original_backend=original_main_object.__class__,
        suggested_main_filename=original_main_object.unpacked_name,
    )


class TestLoadBinaryBlobAddresses(unittest.TestCase):
    """Test the address fields, which are only editable when the binary is loaded as a blob."""

    def setUp(self) -> None:
        create_qapp()

    def test_blob_offers_editable_addresses(self) -> None:
        # this is the fallback LoadBinaryJob uses when a binary cannot be identified
        partial_ld = cle.Loader(BINARY_PATH, main_opts={"backend": "blob", "arch": "x86"})
        dialog = make_dialog(partial_ld)

        for name in ("base_addr", "entry_addr", "offset"):
            assert dialog.option_widgets[name].isEnabled()
            assert dialog.option_widgets[name].text() == "0x0"

        dialog.close()

    def test_recognized_binary_keeps_addresses_read_only(self) -> None:
        partial_ld = cle.Loader(BINARY_PATH, auto_load_libs=False)
        dialog = make_dialog(partial_ld)

        for name in ("base_addr", "entry_addr", "offset"):
            assert not dialog.option_widgets[name].isEnabled()
        assert dialog.option_widgets["base_addr"].text() == hex(partial_ld.main_object.mapped_base)
        assert dialog.option_widgets["entry_addr"].text() == hex(partial_ld.main_object.entry)

        dialog.close()


if __name__ == "__main__":
    unittest.main(argv=[__file__])
