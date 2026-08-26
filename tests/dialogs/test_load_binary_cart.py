"""
Test cases for loading CaRT files, which cle loads through an outer backend.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import cle
from common import AngrManagementTestCase, create_qapp, test_location  # pylint: disable=import-error

import angrmanagement.data.jobs.loading as loading
from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.ui.dialogs.load_binary import LoadBinary

ELF_CART_PATH = os.path.join(test_location, "x86_64", "1after909.cart")
PE_CART_PATH = os.path.join(
    test_location, "x86_64", "windows", "6f289eb8c8cd826525d79b195b1cf187df509d56120427b10ea3fb1b4db1b7b5.sys.cart"
)
CART_KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"
OTHER_KEY = b"0123456789abcdef"


def partial_load(path: str, main_opts: dict | None = None) -> cle.Loader:
    """Partially load a file the same way LoadBinaryJob does."""
    return cle.Loader(
        path,
        perform_relocations=False,
        load_debug_info=False,
        auto_load_libs=False,
        main_opts=dict(main_opts or {}),
    )


def make_dialog(partial_ld: cle.Loader, main_opts: dict | None = None) -> LoadBinary:
    """Build a LoadBinary dialog with the arguments LoadBinaryJob passes."""
    original_main_object = partial_ld.original_main_object
    return LoadBinary(
        partial_ld,
        suggested_backend=partial_ld.main_object.__class__,
        suggested_os_name=partial_ld.main_object.os,
        suggested_main_opts=dict(main_opts or {}),
        suggested_original_backend=original_main_object.__class__,
        suggested_main_filename=original_main_object.unpacked_name,
    )


class TestLoadBinaryCart(unittest.TestCase):
    """Test the LoadBinary dialog when cle unpacked the main object from a CaRT file."""

    def setUp(self) -> None:
        create_qapp()

    def test_elf_cart_splits_main_opts_and_lib_opts(self) -> None:
        partial_ld = partial_load(ELF_CART_PATH, {"arc4_key": CART_KEY})
        dialog = make_dialog(partial_ld, {"arc4_key": CART_KEY})

        assert dialog.option_widgets["outer_backend"].currentText() == "cart"
        assert dialog.option_widgets["backend"].currentText() == "elf"
        # the unpacked object has no path on disk, so the outer backend's name is used
        assert dialog.filename == "1after909.cart.unpacked"

        dialog._on_ok_clicked()

        assert dialog.load_options["main_opts"] == {"backend": "cart", "arc4_key": CART_KEY}
        assert dialog.load_options["lib_opts"] == {"1after909.cart.unpacked": {"backend": "elf"}}

    def test_pe_cart_options_apply_to_the_unpacked_object(self) -> None:
        partial_ld = partial_load(PE_CART_PATH, {"arc4_key": CART_KEY})
        dialog = make_dialog(partial_ld, {"arc4_key": CART_KEY})

        assert dialog.option_widgets["outer_backend"].currentText() == "cart"
        assert dialog.option_widgets["backend"].currentText() == "pe"
        # the unpacked object is a PE, so the debug symbol tab is offered
        assert dialog._symbol_search_tab_index is not None

        dialog._on_ok_clicked()

        assert dialog.load_options["main_opts"] == {"backend": "cart", "arc4_key": CART_KEY}
        lib_opts = dialog.load_options["lib_opts"][partial_ld.original_main_object.unpacked_name]
        assert lib_opts["backend"] == "pe"
        # PE-specific options describe the unpacked object, not the CaRT wrapper
        assert "download_debug_symbols" in lib_opts

    def test_outer_backends_are_not_offered_as_the_inner_backend(self) -> None:
        partial_ld = partial_load(ELF_CART_PATH, {"arc4_key": CART_KEY})
        dialog = make_dialog(partial_ld, {"arc4_key": CART_KEY})

        inner = [dialog.option_widgets["backend"].itemText(i) for i in range(dialog.option_widgets["backend"].count())]
        outer = [
            dialog.option_widgets["outer_backend"].itemText(i)
            for i in range(dialog.option_widgets["outer_backend"].count())
        ]
        assert "cart" in outer
        assert "cart" not in inner
        assert "elf" in inner
        assert "elf" not in outer

    def test_plain_binary_has_no_outer_backend(self) -> None:
        partial_ld = partial_load(os.path.join(test_location, "x86_64", "true"))
        dialog = make_dialog(partial_ld)

        assert dialog.option_widgets["outer_backend"].currentText() == "<None>"
        assert dialog.filename == "true"

        dialog._on_ok_clicked()

        assert dialog.load_options["main_opts"]["backend"] == "elf"
        assert "lib_opts" not in dialog.load_options


class TestForceSetEncryptionKey(unittest.TestCase):
    """Test overriding the encryption key of a CaRT file from the LoadBinary dialog."""

    def setUp(self) -> None:
        create_qapp()
        self.partial_ld = partial_load(ELF_CART_PATH, {"arc4_key": CART_KEY})
        self.dialog = make_dialog(self.partial_ld, {"arc4_key": CART_KEY})

    def tearDown(self) -> None:
        self.dialog.close()

    def test_button_is_only_enabled_for_cart(self) -> None:
        assert self.dialog.option_widgets["enckey_button"].isEnabled()

        self.dialog.option_widgets["outer_backend"].setCurrentText("<None>")
        assert not self.dialog.option_widgets["enckey_button"].isEnabled()

    def test_key_in_use_is_shown(self) -> None:
        assert self.dialog._enckey == CART_KEY
        assert "02 f5 33" in self.dialog.option_widgets["enckey_label"].text()

    def test_overriding_the_key(self) -> None:
        with patch.object(LoadBinary, "_prompt_for_enckey", return_value=OTHER_KEY):
            self.dialog._on_set_enckey_clicked()

        assert self.dialog._enckey == OTHER_KEY
        self.dialog._on_ok_clicked()
        assert self.dialog.load_options["main_opts"]["arc4_key"] == OTHER_KEY

    def test_cancelling_the_prompt_keeps_the_key(self) -> None:
        with patch.object(LoadBinary, "_prompt_for_enckey", return_value=None):
            self.dialog._on_set_enckey_clicked()

        assert self.dialog._enckey == CART_KEY
        self.dialog._on_ok_clicked()
        assert self.dialog.load_options["main_opts"]["arc4_key"] == CART_KEY


class TestLoadBinaryJobCart(AngrManagementTestCase):
    """Test that LoadBinaryJob asks for an encryption key and retries the load with it."""

    def test_job_retries_with_the_user_supplied_key(self) -> None:
        captured = {}

        class FakeEncryptionKeyDialog:
            """Stands in for the modal key prompt."""

            def __init__(self, *args, **kwargs) -> None:
                captured["prompted"] = True
                self.result = CART_KEY

            def exec_(self) -> int:
                return 0

        def fake_load_binary_run(partial_ld, **kwargs):
            captured.update(kwargs)
            return {
                "auto_load_libs": False,
                "main_opts": {"backend": "cart", "arc4_key": CART_KEY},
                "lib_opts": {kwargs["suggested_main_filename"]: {"backend": "elf"}},
            }, None

        with (
            patch.object(loading, "SetEncryptionKeyDialog", FakeEncryptionKeyDialog),
            patch.object(loading.LoadBinary, "run", staticmethod(fake_load_binary_run)),
        ):
            self.main.workspace.job_manager.add_job(LoadBinaryJob(self.main.workspace.main_instance, ELF_CART_PATH))
            self.main.workspace.job_manager.join_all_jobs()

        # the default CaRT key does not work for this file, so the user must have been asked
        assert captured["prompted"] is True
        # the key the user supplied is fed back into the dialog as a suggestion
        assert captured["suggested_main_opts"] == {"arc4_key": CART_KEY}
        assert captured["suggested_original_backend"] is cle.backends.CARTFile
        assert captured["suggested_main_filename"] == "1after909.cart.unpacked"
        assert captured["suggested_backend"] is cle.backends.ELF

        loader = self.main.workspace.main_instance.project.am_obj.loader
        assert isinstance(loader.main_object, cle.backends.ELF)
        assert isinstance(loader.original_main_object, cle.backends.CARTFile)


if __name__ == "__main__":
    unittest.main(argv=[__file__])
