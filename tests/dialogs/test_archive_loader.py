"""
Test cases for ArchiveLoaderDialog and archive utility functions.
"""

# pylint: disable=no-self-use

from __future__ import annotations

import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from common import AngrManagementTestCase  # pylint: disable=import-error
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QTreeWidgetItem

from angrmanagement.ui.dialogs.archive_loader import (
    ArchiveLoaderDialog,
    _extract_tar,
    _extract_zip,
    _format_size,
    _list_tar,
    _list_zip,
    is_archive,
)


def _create_test_zip(path: str, files: dict[str, bytes]) -> None:
    """Create a zip archive with given files."""
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def _create_test_tar(path: str, files: dict[str, bytes]) -> None:
    """Create a tar.gz archive with given files."""
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


TEST_FILES = {
    "hello.txt": b"hello world",
    "subdir/nested.bin": b"\x00\x01\x02\x03",
}


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


class TestArchiveIOUtilities(unittest.TestCase):
    """Test is_archive, _list_zip, _list_tar, _extract_zip, and _extract_tar."""

    def setUp(self):
        self._temp_dir = tempfile.mkdtemp()
        self._zip_path = os.path.join(self._temp_dir, "test.zip")
        self._tar_path = os.path.join(self._temp_dir, "test.tar.gz")
        self._not_archive_path = os.path.join(self._temp_dir, "not_archive.txt")

        _create_test_zip(self._zip_path, TEST_FILES)
        _create_test_tar(self._tar_path, TEST_FILES)

        with open(self._not_archive_path, "w", encoding="utf-8") as f:
            f.write("just plain text")

    def tearDown(self):
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def test_is_archive_zip(self):
        """Test that zip files are detected as archives."""
        assert is_archive(self._zip_path) is True

    def test_is_archive_tar(self):
        """Test that tar files are detected as archives."""
        assert is_archive(self._tar_path) is True

    def test_is_archive_plain_text(self):
        """Test that plain text files are not detected as archives."""
        assert is_archive(self._not_archive_path) is False

    def test_list_zip_returns_all_files(self):
        """Test that _list_zip returns all file members with correct sizes."""
        members = _list_zip(self._zip_path)
        names = {m[0] for m in members}
        assert names == {"hello.txt", "subdir/nested.bin"}
        for name, size in members:
            assert size == len(TEST_FILES[name])

    def test_list_tar_returns_all_files(self):
        """Test that _list_tar returns all file members with correct sizes."""
        members = _list_tar(self._tar_path)
        names = {m[0] for m in members}
        assert names == {"hello.txt", "subdir/nested.bin"}
        for name, size in members:
            assert size == len(TEST_FILES[name])

    def test_extract_zip(self):
        """Test extracting a file from a zip archive."""
        dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
        path = _extract_zip(self._zip_path, "hello.txt", dest_dir)
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            assert f.read() == b"hello world"

    def test_extract_tar(self):
        """Test extracting a file from a tar archive."""
        dest_dir = tempfile.mkdtemp(dir=self._temp_dir)
        path = _extract_tar(self._tar_path, "hello.txt", dest_dir)
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            assert f.read() == b"hello world"


class TestArchiveLoaderDialog(AngrManagementTestCase):
    """Test ArchiveLoaderDialog widget behavior."""

    def setUp(self):
        super().setUp()
        self._temp_dir = tempfile.mkdtemp()
        self._zip_path = os.path.join(self._temp_dir, "test.zip")
        self._tar_path = os.path.join(self._temp_dir, "test.tar.gz")
        self._not_archive_path = os.path.join(self._temp_dir, "not_archive.txt")

        _create_test_zip(self._zip_path, TEST_FILES)
        _create_test_tar(self._tar_path, TEST_FILES)

        with open(self._not_archive_path, "w", encoding="utf-8") as f:
            f.write("just plain text")

    def tearDown(self):
        shutil.rmtree(self._temp_dir, ignore_errors=True)
        super().tearDown()

    def _find_tree_item(self, dlg: ArchiveLoaderDialog, label: str) -> QTreeWidgetItem:
        """Find a top-level tree item by label text."""
        for i in range(dlg._tree.topLevelItemCount()):
            item = dlg._tree.topLevelItem(i)
            assert item is not None
            if item.text(0) == label:
                return item

    def test_tree_contains_expected_items(self):
        """Test that tree widget contains files, directories, and correct UserRole data."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
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
                file_member_paths.append(data)
            else:
                dir_data.append(label)
            for j in range(item.childCount()):
                child = item.child(j)
                all_labels.append(child.text(0))
                child_data = child.data(0, Qt.ItemDataRole.UserRole)
                if child_data is not None:
                    file_member_paths.append(child_data)

        assert "hello.txt" in all_labels
        assert "subdir" in all_labels
        assert "nested.bin" in all_labels
        assert "hello.txt" in file_member_paths
        assert "subdir/nested.bin" in file_member_paths
        assert "subdir" in dir_data
        dlg.close()

    def test_tree_populated_for_tar(self):
        """Test that tree is populated correctly for a tar archive."""
        dlg = ArchiveLoaderDialog(self._tar_path, parent=self.main)
        assert dlg._tree.topLevelItemCount() > 0
        assert dlg._err is None
        dlg.close()

    def test_ok_button_disabled_initially(self):
        """Test that OK button is disabled when no item is selected."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        assert dlg._ok_button.isEnabled() is False
        dlg.close()

    def test_ok_enabled_when_file_selected(self):
        """Test that OK button is enabled when a file item is selected."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        item = self._find_tree_item(dlg, "hello.txt")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        assert dlg._ok_button.isEnabled() is True
        dlg.close()

    def test_ok_disabled_when_directory_selected(self):
        """Test that OK button remains disabled when a directory item is selected."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        item = self._find_tree_item(dlg, "subdir")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        assert dlg._ok_button.isEnabled() is False
        dlg.close()

    def test_accept_extracts_selected_file_zip(self):
        """Test that _on_accept extracts selected file from zip archive."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        item = self._find_tree_item(dlg, "hello.txt")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        dlg._on_accept()
        assert dlg.extracted_file_path is not None
        assert os.path.isfile(dlg.extracted_file_path)
        with open(dlg.extracted_file_path, "rb") as f:
            assert f.read() == b"hello world"
        dlg.cleanup()
        dlg.close()

    def test_accept_extracts_selected_file_tar(self):
        """Test that _on_accept extracts selected file from tar archive."""
        dlg = ArchiveLoaderDialog(self._tar_path, parent=self.main)
        item = self._find_tree_item(dlg, "hello.txt")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        dlg._on_accept()
        assert dlg.extracted_file_path is not None
        assert os.path.isfile(dlg.extracted_file_path)
        with open(dlg.extracted_file_path, "rb") as f:
            assert f.read() == b"hello world"
        dlg.cleanup()
        dlg.close()

    def test_cleanup_removes_temp_directory(self):
        """Test that cleanup removes extracted temp directory and resets state."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        item = self._find_tree_item(dlg, "hello.txt")
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
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        dlg._on_accept()
        assert dlg.extracted_file_path is None
        assert dlg._temp_dir is None
        dlg.close()

    def test_cleanup_is_idempotent(self):
        """Test that calling cleanup multiple times does not raise."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        dlg.cleanup()
        dlg.cleanup()
        dlg.close()

    def test_double_click_file_triggers_accept(self):
        """Test that double-clicking a file item triggers extraction."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        item = self._find_tree_item(dlg, "hello.txt")
        assert item is not None
        dlg._tree.setCurrentItem(item)
        dlg._on_double_click(item, 0)
        assert dlg.extracted_file_path is not None
        dlg.cleanup()
        dlg.close()

    def test_double_click_directory_does_nothing(self):
        """Test that double-clicking a directory item does not trigger extraction."""
        dlg = ArchiveLoaderDialog(self._zip_path, parent=self.main)
        item = self._find_tree_item(dlg, "subdir")
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
