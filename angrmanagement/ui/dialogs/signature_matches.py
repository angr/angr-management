from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QAbstractTableModel, QSize, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QDialog,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QPushButton,
    QRadioButton,
    QTableView,
    QVBoxLayout,
)

if TYPE_CHECKING:
    from angr.flirt import FlirtSignature

    from angrmanagement.data.instance import Instance


class QSignatureMatchesTableModel(QAbstractTableModel):
    """
    Table model for signature matches.
    """

    Headers = ["Function Address", "Function Name", "Conflict"]
    COL_ADDRESS = 0
    COL_NAME = 1
    COL_CONFLICT = 2

    def __init__(self, matches: dict[int, str], instance: Instance) -> None:
        super().__init__()
        self.matches = matches
        self.instance = instance
        self.match_list = sorted(matches.items())  # Sort by address

    def rowCount(self, parent=None) -> int:
        return len(self.match_list)

    def columnCount(self, parent=None) -> int:
        return len(self.Headers)

    def headerData(self, section: int, orientation, role=None):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index, role=None):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            row = index.row()
            col = index.column()
            if row >= len(self.match_list):
                return None

            addr, name = self.match_list[row]
            if col == self.COL_ADDRESS:
                return f"{addr:#x}"
            elif col == self.COL_NAME:
                return name
            elif col == self.COL_CONFLICT:
                # Check if function has a non-default name
                func = self.instance.kb.functions.get(addr)
                if func and not func.is_default_name:
                    # Check if the name matches what we're trying to apply (not a conflict)
                    if func.name == name:
                        return ""
                    # Check if the name is actually a "generic" name that shouldn't count as a conflict
                    name_lower = func.name.lower()
                    if not (name_lower.startswith("unknown") or name_lower.startswith("unresolved") or name_lower.startswith("sub_")):
                        return "✓"
                return ""
        return None


class QSignatureMatchesTable(QTableView):
    """
    Table widget for displaying signature matches.
    """

    def __init__(self, matches: dict[int, str], instance: Instance, parent=None) -> None:
        super().__init__(parent)
        self.instance = instance
        self.matches = matches

        self.horizontalHeader().setVisible(True)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model_obj = QSignatureMatchesTableModel(matches, instance)
        self.setModel(self.model_obj)

        hheader = self.horizontalHeader()
        hheader.setSectionResizeMode(QSignatureMatchesTableModel.COL_ADDRESS, QHeaderView.ResizeMode.ResizeToContents)
        hheader.setSectionResizeMode(QSignatureMatchesTableModel.COL_NAME, QHeaderView.ResizeMode.Stretch)
        hheader.setSectionResizeMode(QSignatureMatchesTableModel.COL_CONFLICT, QHeaderView.ResizeMode.ResizeToContents)

        self.doubleClicked.connect(self._on_double_click)

    def _on_double_click(self, index) -> None:
        """Jump to the function when double-clicked."""
        row = index.row()
        if row >= len(self.model_obj.match_list):
            return
        addr, _name = self.model_obj.match_list[row]
        # Jump to the function address
        from angrmanagement.logic import GlobalInfo

        GlobalInfo.main_window.workspace.jump_to(addr)
        # Close the dialog
        self.window().accept()


class SignatureMatchesDialog(QDialog):
    """
    Dialog displaying matched functions for a signature.
    """

    def __init__(
        self, sig: FlirtSignature, matches: dict[int, str], instance: Instance, signature_mgr, parent=None
    ) -> None:
        super().__init__(parent)
        self.sig = sig
        self.matches = matches
        self.instance = instance
        self.signature_mgr = signature_mgr

        self.setWindowTitle(f"Signature Matches: {sig.sig_name}")
        self._init_widgets()

        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setMinimumSize(self.sizeHint())

    def sizeHint(self):
        return QSize(600, 400)

    def is_conflict(self, addr: int, name: str) -> bool:
        func = self.instance.kb.functions.get(addr)
        if func and not func.is_default_name:
            if func.name == name:
                return False
            name_lower = func.name.lower()
            return not (name_lower.startswith("unknown") or name_lower.startswith("unresolved") or name_lower.startswith("sub_"))
        return False

    def _init_widgets(self) -> None:
        table = QSignatureMatchesTable(self.matches, self.instance, self)

        # Count conflicts
        conflict_count = 0
        total_matches = len(self.matches)
        for addr, name in self.matches.items():
            if self.is_conflict(addr, name):
                    conflict_count += 1

        # Conflict resolution radio buttons
        conflict_group = QGroupBox(f"Conflict Resolution ({conflict_count}/{total_matches} conflicts)")
        conflict_layout = QHBoxLayout()

        self.overwrite_radio = QRadioButton("Overwrite")
        self.ignore_radio = QRadioButton("Ignore")
        self.overwrite_radio.setChecked(True)  # Default to Overwrite

        self.conflict_button_group = QButtonGroup()
        self.conflict_button_group.addButton(self.overwrite_radio)
        self.conflict_button_group.addButton(self.ignore_radio)

        conflict_layout.addWidget(self.overwrite_radio)
        conflict_layout.addWidget(self.ignore_radio)
        conflict_layout.addStretch()
        conflict_group.setLayout(conflict_layout)

        # Apply button
        apply_button = QPushButton("Apply Functions")
        apply_button.clicked.connect(self._on_apply_functions)

        # Main layout
        layout = QVBoxLayout()
        layout.addWidget(table)
        layout.addWidget(conflict_group)
        layout.addWidget(apply_button)
        self.setLayout(layout)

    def _on_apply_functions(self) -> None:
        """Handle Apply Functions button click."""
        ignore_addresses = set()

        if self.ignore_radio.isChecked():
            for addr, name in self.matches.items():
                if self.is_conflict(addr, name):
                    ignore_addresses.add(addr)

        self.signature_mgr.apply_signatures([self.sig], dry_run=False, ignore_addresses=ignore_addresses)
        self.accept()
