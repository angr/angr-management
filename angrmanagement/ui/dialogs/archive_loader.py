from __future__ import annotations

import os
import shutil
import tempfile

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from angrmanagement.utils.archive import (
    Archive,
    ArchiveError,
    ArchiveInvalidPassword,
    ArchiveMember,
    ArchivePasswordRequired,
    get_archive_object,
)


def _format_size(size: int) -> str:
    s: float = size
    for unit in ("B", "KB", "MB", "GB"):
        if s < 1024:
            return f"{s:.0f} {unit}" if unit == "B" else f"{s:.1f} {unit}"
        s /= 1024
    return f"{s:.1f} TB"


class ArchiveLoaderDialog(QDialog):
    """Dialog that lets the user pick a file from inside an archive to load."""

    def __init__(self, archive_path: str, parent=None) -> None:
        super().__init__(parent)
        self.archive_path = archive_path
        self.extracted_file_path: str | None = None
        self._temp_dir: str | None = None
        self._err: str | None = None
        self._password: str | None = None
        self._archive_obj: Archive | None = None
        try:
            self._archive_obj = get_archive_object(archive_path)
        except ArchiveError as e:
            self._err = str(e)

        self.setWindowTitle("Load File from Archive")
        self.setMinimumSize(500, 400)

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
        if self._archive_obj is None:
            return

        try:
            members = self._archive_obj.list_members()
            members.sort(key=lambda m: m.name)
        except ArchiveError as e:
            self._err = str(e)
            return

        nodes: dict[str, QTreeWidgetItem] = {}

        for member in members:
            parts = member.name.split("/")
            for i, part in enumerate(parts):
                key = "/".join(parts[: i + 1])
                if key in nodes:
                    continue
                item = QTreeWidgetItem()
                item.setText(0, part)
                is_file = i == len(parts) - 1
                if is_file:
                    item.setData(0, Qt.ItemDataRole.UserRole, member)
                    item.setText(1, _format_size(member.size))
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
        if member is not None and isinstance(member, ArchiveMember):
            self._on_accept()

    def _on_accept(self) -> None:
        current = self._tree.currentItem()
        if current is None:
            return
        member = current.data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(member, ArchiveMember):
            return
        if self._archive_obj is None:
            return

        password: str | None = None
        while True:
            if member.encrypted:
                password = self._prompt_for_password(member)
                if password is None:
                    return

            try:
                self._temp_dir = tempfile.mkdtemp(prefix="angr_management_archive_")
                self.extracted_file_path = self._archive_obj.extract(member.name, self._temp_dir, password=password)

                # Sanity check
                if not os.path.isfile(self.extracted_file_path):
                    self.extracted_file_path = None
                    raise ArchiveError("Extracted path is not a file")

            except ArchivePasswordRequired:
                self._cleanup_extraction()
                member = ArchiveMember(member.name, member.size, encrypted=True)
                continue
            except ArchiveInvalidPassword as e:
                self._cleanup_extraction()
                QMessageBox.warning(self, "Incorrect Password", str(e))
                continue
            except ArchiveError as e:
                QMessageBox.critical(self, "Extraction Error", f"Failed to extract file: {e}")
                self.cleanup()
                return

            if password is not None:
                self._password = password
            break

        self._close_archive()
        self.accept()

    def _prompt_for_password(self, member: ArchiveMember) -> str | None:
        password, ok = QInputDialog.getText(
            self,
            "Archive Password",
            f"Password required for {member.name}:",
            QLineEdit.EchoMode.Password,
            self._password or "",
        )
        if not ok:
            return None
        return password

    def _cleanup_extraction(self) -> None:
        if self._temp_dir and os.path.isdir(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None
            self.extracted_file_path = None

    def _close_archive(self) -> None:
        if self._archive_obj is not None:
            self._archive_obj.close()
            self._archive_obj = None

    def exec(self) -> int:
        if self._err is not None:
            QMessageBox.critical(self, "Error", self._err)
            return QDialog.DialogCode.Rejected
        return super().exec()

    def cleanup(self) -> None:
        self._close_archive()
        self._cleanup_extraction()
