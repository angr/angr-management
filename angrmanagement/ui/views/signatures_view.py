from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from angrmanagement.present.signatures import SignaturesPresenter, SignaturesTableModel
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

from .view import InstanceView

_l = logging.getLogger(name=__name__)

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.data.signatures import SignatureManager
    from angrmanagement.ui.workspace import Workspace


class QSignatureTableModel(QtTableModelAdapter):
    """
    Signature table model: a Qt model over a :class:`~angrmanagement.present.signatures.SignaturesTableModel`.
    """

    Headers = SignaturesTableModel.Headers
    COL_TYPE = SignaturesTableModel.COL_TYPE
    COL_NAME = SignaturesTableModel.COL_NAME
    COL_ARCH = SignaturesTableModel.COL_ARCH
    COL_PLATFORM = SignaturesTableModel.COL_PLATFORM
    COL_COMPILER = SignaturesTableModel.COL_COMPILER
    COL_OS_NAME = SignaturesTableModel.COL_OS_NAME
    COL_MATCHES = SignaturesTableModel.COL_MATCHES

    table_model: SignaturesTableModel

    def __init__(self, signature_mgr: SignatureManager, table_model: SignaturesTableModel | None = None) -> None:
        super().__init__(table_model if table_model is not None else SignaturesTableModel(signature_mgr), None, False)
        self.signature_mgr = signature_mgr
        self._owns_table_model = table_model is None

    def shutdown(self) -> None:
        if self._owns_table_model:
            self.table_model.shutdown()


class QSignatureTableWidget(QTableView):
    """
    Signature table widget.
    """

    def __init__(self, signature_mgr, workspace: Workspace, presenter: SignaturesPresenter | None = None) -> None:
        super().__init__()
        self.workspace = workspace
        self.signature_mgr = signature_mgr
        self.presenter = presenter

        hheader = self.horizontalHeader()
        hheader.setVisible(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QSignatureTableModel = QSignatureTableModel(
            self.signature_mgr, presenter.model if presenter is not None else None
        )
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
        sigs = self.model.table_model.objects(i.row() for i in self.selectedIndexes())
        if self.presenter is not None:
            menu = self.presenter.signatures_menu(sigs, show_matches=self._show_matches_dialog)
            menu.qmenu(cached=False).exec_(event.globalPos())

    # pylint:disable=unused-argument
    def _on_cell_double_click(self, index) -> None:
        """Double-click: try applying signature if not yet applied, otherwise show matches dialog."""
        sig = self.model.table_model.row(index.row())
        if sig is None:
            return
        if self.presenter is not None:
            self.presenter.open_signature(sig, show_matches=self._show_matches_dialog)
            return
        matches = self.signature_mgr.get_matches(sig)
        if matches:
            self._show_matches_dialog(sig, matches)
        else:
            self.signature_mgr.apply_signatures([sig], dry_run=True)

    def _apply_and_refresh(self, sigs) -> None:
        self.signature_mgr.apply_signatures(sigs, dry_run=False)
        self.workspace.on_flirt_signatures_applied()

    def _show_matches_dialog(self, sig, matches) -> None:
        """Show dialog displaying matched functions for a signature."""
        from angrmanagement.ui.dialogs.signature_matches import (  # pylint:disable=import-outside-toplevel
            SignatureMatchesDialog,
        )

        dialog = SignatureMatchesDialog(sig, matches, self.workspace.main_instance, self.signature_mgr, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.workspace.on_flirt_signatures_applied()


class SignaturesView(InstanceView):
    """
    Signatures view that displays all loaded (FLIRT) signatures and their statuses.
    """

    presenter: SignaturesPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "signatures",
            workspace,
            default_docking_position,
            instance,
            SignaturesPresenter(workspace, instance, default_docking_position),
        )
        self.base_caption = "Function Signatures"
        self._tbl_widget: QSignatureTableWidget | None = None
        self._init_widgets()
        self.reload()

    def reload(self) -> None:
        self.presenter.reload()

    def closeEvent(self, event) -> None:
        self.presenter.close()
        super().closeEvent(event)

    # pylint:disable=no-self-use
    def minimumSizeHint(self):
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        # Header with buttons
        header_layout = QHBoxLayout()

        load_btn = QPushButton("Load Signature Files...")
        load_btn.clicked.connect(self.instance.signature_mgr.load_signatures)

        try_all_btn = QPushButton("Try Applying All Signatures")
        try_all_btn.clicked.connect(self._try_apply_all_signatures)

        bindiff_btn = QPushButton("Find Matches Via Bindiff")
        bindiff_btn.clicked.connect(self._find_matches_via_bindiff)

        header_layout.addWidget(load_btn)
        header_layout.addWidget(try_all_btn)
        header_layout.addWidget(bindiff_btn)
        header_layout.addStretch()

        # Main layout
        vlayout = QVBoxLayout()
        vlayout.addLayout(header_layout)
        self._tbl_widget = QSignatureTableWidget(self.instance.signature_mgr, self.workspace, self.presenter)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)

    def _try_apply_all_signatures(self) -> None:
        """Try applying all signatures in the view."""
        self.presenter.try_all_signatures()

    def _find_matches_via_bindiff(self) -> None:
        """Launch a background job to find matches via bindiff."""
        self.presenter.find_matches_via_bindiff()
