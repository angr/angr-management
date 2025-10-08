from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QSize, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QTableView, QVBoxLayout

from .view import InstanceView

if TYPE_CHECKING:

    import PySide6
    from angr.flirt import FlirtSignature

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.signatures import SignatureManager
    from angrmanagement.ui.workspace import Workspace


class QSignatureTableModel(QAbstractTableModel):
    """
    Signature table model.
    """

    Headers = [
        "Type",
        "Name",
        "Architecture",
        "Platform",
        "Compiler",
        "OS Name",
        "Matches",
    ]
    COL_TYPE = 0
    COL_NAME = 1
    COL_ARCH = 2
    COL_PLATFORM = 3
    COL_COMPILER = 4
    COL_OS_NAME = 5
    COL_MATCHES = 6

    def __init__(self, signature_mgr: SignatureManager) -> None:
        super().__init__()
        self.signature_mgr = signature_mgr
        self.signature_mgr.signatures.am_subscribe(self._on_signatures_updated)

    def _on_signatures_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.beginResetModel()
        self.endResetModel()

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self.signature_mgr.signatures)

    def columnCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self.Headers)

    # pylint:disable=unused-argument
    def headerData(self, section: int, orientation: PySide6.QtCore.Qt.Orientation, role: int = ...) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index: PySide6.QtCore.QModelIndex, role: int = ...) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        if row >= len(self.signature_mgr.signatures):
            return None
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_column_text(self.signature_mgr.signatures[row], col)
        else:
            return None

    def _get_column_text(self, sig: FlirtSignature, column: int) -> str:
        if column == self.COL_TYPE:
            return "FLIRT"
        elif column == self.COL_NAME:
            return sig.sig_name
        elif column == self.COL_ARCH:
            return sig.arch
        elif column == self.COL_PLATFORM:
            return sig.platform
        elif column == self.COL_COMPILER:
            return sig.compiler
        elif column == self.COL_OS_NAME:
            return sig.os_name
        elif column == self.COL_MATCHES:
            m = self.signature_mgr.get_match_count(sig)
            return str(m) if m is not None else "N/A"
        else:
            raise AssertionError


class QSignatureTableWidget(QTableView):
    """
    Signature table widget.
    """

    def __init__(self, signature_mgr, workspace: Workspace) -> None:
        super().__init__()
        self.workspace = workspace
        self.signature_mgr = signature_mgr

        hheader = self.horizontalHeader()
        hheader.setVisible(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QSignatureTableModel = QSignatureTableModel(self.signature_mgr)
        self.setModel(self.model)

        for col in range(len(QSignatureTableModel.Headers)):
            hheader.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        hheader.setStretchLastSection(True)
        self.doubleClicked.connect(self._on_cell_double_click)

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self.model.shutdown()
        super().closeEvent(event)

    def contextMenuEvent(self, event) -> None:
        selected_rows = {i.row() for i in self.selectedIndexes()}
        sigs = [self.signature_mgr.signatures[r] for r in selected_rows]
        menu = QMenu("", self)
        if len(sigs):
            menu.addAction(
                "&Try applying signature(s)", lambda: self.signature_mgr.apply_signatures(sigs, dry_run=True)
            )
            menu.addAction("&Apply signature(s)", lambda: self.signature_mgr.apply_signatures(sigs, dry_run=False))
            menu.addSeparator()
        menu.addAction("&Load signature files...", self.signature_mgr.load_signatures)
        menu.exec_(event.globalPos())

    # pylint:disable=unused-argument,no-self-use
    def _on_cell_double_click(self, index) -> None:
        return


class SignaturesView(InstanceView):
    """
    Signatures view that displays all loaded (FLIRT) signatures and their statuses.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("signatures", workspace, default_docking_position, instance)
        self.base_caption = "Function Signatures"
        self._tbl_widget: QSignatureTableWidget | None = None
        self._init_widgets()
        self.reload()

    def reload(self) -> None:
        self.instance.signature_mgr.sync_from_angr()

    # pylint:disable=no-self-use
    def minimumSizeHint(self):
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        vlayout = QVBoxLayout()
        self._tbl_widget = QSignatureTableWidget(self.instance.signature_mgr, self.workspace)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
