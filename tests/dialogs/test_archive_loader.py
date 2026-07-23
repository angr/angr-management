"""
Test cases for ArchiveLoaderDialog and archive utility functions.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import io
import os
import shutil
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from common import AngrManagementTestCase, test_location  # pylint: disable=import-error
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QTreeWidgetItem

from angrmanagement.ui.dialogs.archive_loader import (
    ArchiveLoaderDialog,
    _format_size,
)
from angrmanagement.utils.archive import (
    ArchiveError,
    ArchiveInvalidPassword,
    ArchiveMember,
    ArchivePasswordRequired,
    TarArchive,
    ZipArchive,
    get_archive_object,
    is_archive,
)

ZIP_PATH = os.path.join(test_location, "x86_64", "test_zip_archive.zip")
TAR_PATH = os.path.join(test_location, "x86_64", "test_tar_archive.tar")
ENC_ZIP_PATH = os.path.join(test_location, "x86_64", "test_enc_zip_archive.zip")
ENC_ZIP_PASSWORD = "infected"

ZIP_MEMBERS = {"fauxware": 8776, "subfolder/fauxware_reflow": 16328}
TAR_MEMBERS = {"./fauxware": 8776, "./subfolder/fauxware_reflow": 16328}
ELF_MAGIC = b"\x7fELF"


class TestFormatSize(unittest.TestCase):
    """Test _format_size utility function."""

    def test_bytes(self):
        """Test formatting of byte-sized values."""
        assert _format_size(0) == "0 B"
        assert _format_size(512) == "512 B"
        assert _format_size(1023) == "1023 B"

    def test_kilobytes(self):
        """Test formatting of kilobyte-sized values."""
        assert _format_size(1024) == "1.0 KB"
        assert _format_size(1536) == "1.5 KB"

    def test_larger_units(self):
        """Test formatting of MB, GB, and TB values."""
        assert _format_size(1024 * 1024) == "1.0 MB"
        assert _format_size(1024**3) == "1.0 GB"
        assert _format_size(1024**4) == "1.0 TB"


class TestArchiveClasses(unittest.TestCase):
    """Test archive detection, listing, and extraction."""

    def setUp(self):
        self._temp_dir = tempfile.mkdtemp()
        self._not_archive_path = os.path.join(self._temp_dir, "not_archive.txt")
        with open(self._not_archive_path, "w", encoding="utf-8") as f:
            f.write("just plain text")

    def tearDown(self):
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def test_is_archive_zip(self):
        """Test that zip files are detected as archives."""
        assert is_archive(ZIP_PATH) is True

    def test_is_archive_tar(self):
        """Test that tar files are detected as archives."""
        assert is_archive(TAR_PATH) is True

    def test_is_archive_plain_text(self):
        """Test that plain text files are not detected as archives."""
        assert is_archive(self._not_archive_path) is False

    def test_is_archive_binary_with_embedded_zip(self):
        """Test that a binary with zip data appended is not detected as an archive."""
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("payload.txt", "embedded zip member")

        embedded_path = os.path.join(self._temp_dir, "elf_with_zip")
        with open(embedded_path, "wb") as f:
            f.write(ELF_MAGIC + b"\x00" * 128 + zip_buf.getvalue())

        assert ZipArchive.is_type(embedded_path) is False
        assert is_archive(embedded_path) is False

    def test_get_archive_object(self):
        """Test that get_archive_object returns the right type or raises error."""
        with get_archive_object(ZIP_PATH) as archive:
            assert isinstance(archive, ZipArchive)

        with get_archive_object(ENC_ZIP_PATH) as archive:
            assert isinstance(archive, ZipArchive)

        with get_archive_object(TAR_PATH) as archive:
            assert isinstance(archive, TarArchive)

        with self.assertRaises(ArchiveError):
            get_archive_object(self._not_archive_path)

    def test_zip_lists_all_files(self):
        """Test that ZipArchive returns all file members with correct sizes."""
        with ZipArchive(ZIP_PATH) as archive:
            members = archive.list_members()
            member_map = {m.name: m for m in members}
            assert set(member_map) == set(ZIP_MEMBERS)
            for name, expected_size in ZIP_MEMBERS.items():
                assert member_map[name].size == expected_size
                assert member_map[name].encrypted is False

    def test_enc_zip_lists_all_files(self):
        """Test that ZipArchive returns all file members with correct sizes."""
        with ZipArchive(ENC_ZIP_PATH) as archive:
            members = archive.list_members()
            member_map = {m.name: m for m in members}
            assert set(member_map) == set(ZIP_MEMBERS)
            for name, expected_size in ZIP_MEMBERS.items():
                assert member_map[name].size == expected_size
                assert member_map[name].encrypted is True

    def test_tar_lists_all_files(self):
        """Test that TarArchive returns all file members with correct sizes."""
        with TarArchive(TAR_PATH) as archive:
            members = archive.list_members()
            member_map = {m.name: m for m in members}
            assert set(member_map) == set(TAR_MEMBERS)
            for name, expected_size in TAR_MEMBERS.items():
                assert member_map[name].size == expected_size
                assert member_map[name].encrypted is False

    def test_zip_extract(self):
        """Test extracting a file from a zip archive."""
        with ZipArchive(ZIP_PATH) as archive:
            dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
            path = archive.extract("fauxware", dest_dir)
            assert os.path.isfile(path)

    def test_operations_fail_after_close(self):
        """Test that callers cannot use an archive after closing it."""
        archive = get_archive_object(ZIP_PATH)
        archive.close()
        with self.assertRaises(ArchiveError):
            archive.list_members()

    def test_zip_extract_encrypted_without_password_fails(self):
        """Test that encrypted zip members require a password."""
        with ZipArchive(ENC_ZIP_PATH) as backend:
            dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
            with self.assertRaises(ArchivePasswordRequired):
                backend.extract("fauxware", dest_dir)

    def test_zip_extract_encrypted_with_password(self):
        """Test extracting a password-protected file from a zip archive."""
        with ZipArchive(ENC_ZIP_PATH) as backend:
            dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
            path = backend.extract("fauxware", dest_dir, password=ENC_ZIP_PASSWORD)
            assert os.path.isfile(path)

    def test_zip_extract_encrypted_with_wrong_password_fails(self):
        """Test that encrypted zip members reject wrong passwords."""
        with ZipArchive(ENC_ZIP_PATH) as backend:
            dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
            with self.assertRaises(ArchiveInvalidPassword):
                backend.extract("fauxware", dest_dir, password="wrong")

    def test_tar_extract(self):
        """Test extracting a file from a tar archive."""
        with TarArchive(TAR_PATH) as backend:
            dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
            path = backend.extract("./fauxware", dest_dir)
            assert os.path.isfile(path)


class TestArchiveLoaderDialog(AngrManagementTestCase):
    """Test ArchiveLoaderDialog widget behavior."""

    def setUp(self):
        super().setUp()
        self._temp_dir = tempfile.mkdtemp()
        self._not_archive_path = os.path.join(self._temp_dir, "not_archive.txt")
        with open(self._not_archive_path, "w", encoding="utf-8") as f:
            f.write("just plain text")

    def tearDown(self):
        shutil.rmtree(self._temp_dir, ignore_errors=True)
        super().tearDown()

    def _find_tree_item(self, dlg: ArchiveLoaderDialog, label: str) -> QTreeWidgetItem | None:
        """Find a top-level tree item by label text."""
        for i in range(dlg._tree.topLevelItemCount()):
            item = dlg._tree.topLevelItem(i)
            assert item is not None
            if item.text(0) == label:
                return item
        return None

    def test_tree_contains_expected_items(self):
        """Test that tree widget contains files, directories, and correct UserRole data."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        all_labels: list[str] = []
        file_member_paths: list[str] = []
        dir_data: list[str] = []

        for i in range(dlg._tree.topLevelItemCount()):
            item = dlg._tree.topLevelItem(i)
            assert item is not None
            label = item.text(0)
            all_labels.append(label)
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if data is not None:
                assert isinstance(data, ArchiveMember)
                file_member_paths.append(data.name)
            else:
                dir_data.append(label)
            for j in range(item.childCount()):
                child = item.child(j)
                all_labels.append(child.text(0))
                child_data = child.data(0, Qt.ItemDataRole.UserRole)
                if child_data is not None:
                    assert isinstance(child_data, ArchiveMember)
                    file_member_paths.append(child_data.name)

        assert "fauxware" in all_labels
        assert "subfolder" in all_labels
        assert "fauxware_reflow" in all_labels
        assert "fauxware" in file_member_paths
        assert "subfolder/fauxware_reflow" in file_member_paths
        assert "subfolder" in dir_data
        dlg.close()

    def test_tree_populated_for_tar(self):
        """Test that tree is populated correctly for a tar archive."""
        dlg = ArchiveLoaderDialog(TAR_PATH, parent=self.main)
        assert dlg._tree.topLevelItemCount() > 0
        assert dlg._err is None
        dlg.close()

    def test_tree_populated_for_enc_zip(self):
        """Test that tree is populated correctly for a encrypted zip archive."""
        dlg = ArchiveLoaderDialog(ENC_ZIP_PATH, parent=self.main)
        assert dlg._tree.topLevelItemCount() > 0
        assert dlg._err is None
        dlg.close()

    def test_ok_button_disabled_initially(self):
        """Test that OK button is disabled when no item is selected."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        assert dlg._ok_button.isEnabled() is False
        dlg.close()

    def test_ok_enabled_when_file_selected(self):
        """Test that OK button is enabled when a file item is selected."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        assert dlg._ok_button.isEnabled() is True
        dlg.close()

    def test_ok_disabled_when_directory_selected(self):
        """Test that OK button remains disabled when a directory item is selected."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "subfolder")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        assert dlg._ok_button.isEnabled() is False
        dlg.close()

    def test_accept_extracts_selected_file_zip(self):
        """Test that _on_accept extracts selected file from zip archive."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        dlg._on_accept()
        assert dlg.extracted_file_path is not None
        assert os.path.isfile(dlg.extracted_file_path)
        dlg.cleanup()
        dlg.close()

    def test_accept_extracts_selected_file_tar(self):
        """Test that _on_accept extracts selected file from tar archive."""
        dlg = ArchiveLoaderDialog(TAR_PATH, parent=self.main)
        item = self._find_tree_item(dlg, ".")
        assert item is not None
        fauxware_child = None
        for i in range(item.childCount()):
            child = item.child(i)
            if child.text(0) == "fauxware":
                fauxware_child = child
                break
        assert fauxware_child is not None
        dlg._tree.setCurrentItem(fauxware_child)
        dlg._on_accept()
        assert dlg.extracted_file_path is not None
        assert os.path.isfile(dlg.extracted_file_path)
        dlg.cleanup()
        dlg.close()

    def test_accept_extracts_password_protected_zip(self):
        """Test that _on_accept prompts for password and extracts an encrypted zip member."""
        dlg = ArchiveLoaderDialog(ENC_ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        with patch(
            "angrmanagement.ui.dialogs.archive_loader.QInputDialog.getText",
            return_value=(ENC_ZIP_PASSWORD, True),
        ) as prompt:
            dlg._on_accept()
        prompt.assert_called_once()
        assert dlg.extracted_file_path is not None
        assert os.path.isfile(dlg.extracted_file_path)
        dlg.cleanup()
        dlg.close()

    def test_accept_password_prompt_cancel_does_not_extract(self):
        """Test that canceling the password prompt leaves the dialog open."""
        dlg = ArchiveLoaderDialog(ENC_ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        with patch(
            "angrmanagement.ui.dialogs.archive_loader.QInputDialog.getText",
            return_value=("", False),
        ):
            dlg._on_accept()
        assert dlg.extracted_file_path is None
        assert dlg._temp_dir is None
        dlg.close()

    def test_accept_reprompts_after_wrong_password(self):
        """Test that a bad password does not close the dialog and can be retried."""
        dlg = ArchiveLoaderDialog(ENC_ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        with (
            patch(
                "angrmanagement.ui.dialogs.archive_loader.QInputDialog.getText",
                side_effect=[("wrong", True), (ENC_ZIP_PASSWORD, True)],
            ) as prompt,
            patch("angrmanagement.ui.dialogs.archive_loader.QMessageBox.warning") as warning,
        ):
            dlg._on_accept()
        assert prompt.call_count == 2
        warning.assert_called_once()
        assert dlg._password == ENC_ZIP_PASSWORD
        assert dlg.extracted_file_path is not None
        assert os.path.isfile(dlg.extracted_file_path)
        dlg.cleanup()
        dlg.close()

    def test_cleanup_removes_temp_directory(self):
        """Test that cleanup removes extracted temp directory and resets state."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        dlg._on_accept()
        temp_dir = dlg._temp_dir
        assert temp_dir is not None
        assert os.path.isdir(temp_dir)
        dlg.cleanup()
        assert not os.path.isdir(temp_dir)
        assert dlg._temp_dir is None
        assert dlg.extracted_file_path is None
        dlg.close()

    def test_invalid_archive_sets_error(self):
        """Test that opening a non-archive file sets error message."""
        dlg = ArchiveLoaderDialog(self._not_archive_path, parent=self.main)
        assert dlg._err is not None
        dlg.close()

    def test_accept_with_no_selection_does_nothing(self):
        """Test that _on_accept with no current item is a no-op."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        dlg._on_accept()
        assert dlg.extracted_file_path is None
        assert dlg._temp_dir is None
        dlg.close()

    def test_double_click_file_triggers_accept(self):
        """Test that double-clicking a file item triggers extraction."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "fauxware")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        dlg._on_double_click(item, 0)
        assert dlg.extracted_file_path is not None
        dlg.cleanup()
        dlg.close()

    def test_double_click_directory_does_nothing(self):
        """Test that double-clicking a directory item does not trigger extraction."""
        dlg = ArchiveLoaderDialog(ZIP_PATH, parent=self.main)
        item = self._find_tree_item(dlg, "subfolder")
        assert item is not None
        dlg._on_double_click(item, 0)
        assert dlg.extracted_file_path is None
        dlg.close()

    def test_exec_with_error_returns_rejected(self):
        """Test that exec() returns Rejected when archive has error."""
        dlg = ArchiveLoaderDialog(self._not_archive_path, parent=self.main)
        assert dlg._err is not None
        with patch("angrmanagement.ui.dialogs.archive_loader.QMessageBox.critical"):
            result = dlg.exec()
        assert result == QDialog.DialogCode.Rejected
        dlg.close()


if __name__ == "__main__":
    unittest.main()
