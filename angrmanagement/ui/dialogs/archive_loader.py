from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
import zipfile

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QLabel,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)


def is_archive(file_path: str) -> bool:
    return zipfile.is_zipfile(file_path) or tarfile.is_tarfile(file_path)


def _list_zip(path: str) -> list[tuple[str, int]]:
    with zipfile.ZipFile(path, "r") as zf:
        return [(i.filename, i.file_size) for i in zf.infolist() if not i.is_dir()]


def _list_tar(path: str) -> list[tuple[str, int]]:
    with tarfile.open(path, "r:*") as tf:
        return [(m.name, m.size) for m in tf.getmembers() if m.isfile()]


def _format_size(size: int) -> str:
    s: float = size
    for unit in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.0f} {unit}" if unit == "B" else f"{s:.1f} {unit}"
        s /= 1024
    return f"{s:.1f} TB"


def _extract_zip(archive_path: str, member: str, dest_dir: str) -> str:
    with zipfile.ZipFile(archive_path, "r") as zf:
        zf.extract(member, dest_dir)
    dest = os.path.join(dest_dir, member)
    return dest


def _extract_tar(archive_path: str, member: str, dest_dir: str) -> str:
    with tarfile.open(archive_path, "r:*") as tf:
        tf.extract(member, dest_dir, filter="data")
    dest = os.path.join(dest_dir, member)
    return dest


class ArchiveLoaderDialog(QDialog):
    """Dialog that lets the user pick a file from inside an archive to load."""

    def __init__(self, archive_path: str, parent=None) -> None:
        super().__init__(parent)
        self.archive_path = archive_path
        self.extracted_file_path: str | None = None
        self._temp_dir: str | None = None
        self._err: str | None = None

        self.setWindowTitle("Load File from Archive")
        self.setMinimumSize(500, 400)

        self._is_zip = zipfile.is_zipfile(archive_path)
        self._is_tar = tarfile.is_tarfile(archive_path) if not self._is_zip else False

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"Archive: {os.path.basename(archive_path)}"))

        self._tree = QTreeWidget()
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(["Name", "Size"])
        self._tree.header().setStretchLastSection(False)
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        layout.addWidget(self._tree)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok_button.setEnabled(False)
        layout.addWidget(buttons)

        self.setLayout(layout)

        self._tree.currentItemChanged.connect(self._on_selection_changed)
        self._populate_tree()

    def _populate_tree(self) -> None:
        try:
            members = _list_zip(self.archive_path) if self._is_zip else _list_tar(self.archive_path)
        except (zipfile.BadZipFile, tarfile.TarError, OSError) as e:
            self._err = f"Failed to read archive: {e}"
            return

        members.sort(key=lambda m: m[0])
        nodes: dict[str, QTreeWidgetItem] = {}

        for name, size in members:
            parts = name.split("/")
            for i, part in enumerate(parts):
                key = "/".join(parts[: i + 1])
                if key in nodes:
                    continue
                item = QTreeWidgetItem()
                item.setText(0, part)
                is_file = i == len(parts) - 1
                if is_file:
                    item.setData(0, Qt.ItemDataRole.UserRole, name)
                    item.setText(1, _format_size(size))
                    item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                else:
                    item.setData(0, Qt.ItemDataRole.UserRole, None)
                if i == 0:
                    self._tree.addTopLevelItem(item)
                else:
                    parent_key = "/".join(parts[:i])
                    nodes[parent_key].addChild(item)
                nodes[key] = item

        self._tree.expandAll()

    def _on_selection_changed(self, current: QTreeWidgetItem, _previous: QTreeWidgetItem) -> None:
        if current is None:
            self._ok_button.setEnabled(False)
            return
        member = current.data(0, Qt.ItemDataRole.UserRole)
        self._ok_button.setEnabled(member is not None)

    def _on_double_click(self, item: QTreeWidgetItem, _column: int) -> None:
        member = item.data(0, Qt.ItemDataRole.UserRole)
        if member is not None:
            self._on_accept()

    def _on_accept(self) -> None:
        current = self._tree.currentItem()
        if current is None:
            return
        member = current.data(0, Qt.ItemDataRole.UserRole)
        if member is None:
            return

        try:
            self._temp_dir = tempfile.mkdtemp(prefix="angr_management_archive_")
            if self._is_zip:
                self.extracted_file_path = _extract_zip(self.archive_path, member, self._temp_dir)
            else:
                self.extracted_file_path = _extract_tar(self.archive_path, member, self._temp_dir)

            # Sanity check
            if not os.path.isfile(self.extracted_file_path):
                self.extracted_file_path = None
                raise ValueError("Extracted path is not a file")

        except (zipfile.BadZipFile, tarfile.TarError, OSError, ValueError) as e:
            QMessageBox.critical(self, "Extraction Error", f"Failed to extract file: {e}")
            self.cleanup()
            return

        self.accept()

    def exec(self) -> int:
        if self._err is not None:
            QMessageBox.critical(self, "Error", self._err)
            return QDialog.DialogCode.Rejected
        return super().exec()

    def cleanup(self) -> None:
        if self._temp_dir and os.path.isdir(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
            self.extracted_file_path = None
