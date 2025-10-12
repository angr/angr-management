from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QAbstractTableModel, QSize, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHeaderView,
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

    Headers = ["Function Address", "Function Name"]
    COL_ADDRESS = 0
    COL_NAME = 1

    def __init__(self, matches: dict[int, str]) -> None:
        super().__init__()
        self.matches = matches
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

        self.model_obj = QSignatureMatchesTableModel(matches)
        self.setModel(self.model_obj)

        hheader = self.horizontalHeader()
        hheader.setSectionResizeMode(QSignatureMatchesTableModel.COL_ADDRESS, QHeaderView.ResizeMode.ResizeToContents)
        hheader.setSectionResizeMode(QSignatureMatchesTableModel.COL_NAME, QHeaderView.ResizeMode.Stretch)

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

    def __init__(self, sig: FlirtSignature, matches: dict[int, str], instance: Instance, parent=None) -> None:
        super().__init__(parent)
        self.sig = sig
        self.matches = matches
        self.instance = instance

        self.setWindowTitle(f"Signature Matches: {sig.sig_name}")
        self._init_widgets()

        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint | Qt.WindowType.WindowCloseButtonHint
        )
        self.setMinimumSize(self.sizeHint())

    def sizeHint(self):
        return QSize(600, 400)

    def _init_widgets(self) -> None:
        table = QSignatureMatchesTable(self.matches, self.instance, self)

        layout = QVBoxLayout()
        layout.addWidget(table)
        self.setLayout(layout)
