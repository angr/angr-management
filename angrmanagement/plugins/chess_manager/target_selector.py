# pylint:disable=unused-argument
import typing
from typing import List, Optional, TYPE_CHECKING
import threading

import asyncio
from tornado.platform.asyncio import AnyThreadEventLoopPolicy

import PySide2
from PySide2.QtWidgets import QDialog, QPushButton, QHBoxLayout, QVBoxLayout, QMessageBox, QTableView, \
    QAbstractItemView, QHeaderView, QLabel
from PySide2.QtCore import Qt, QAbstractTableModel

try:
    import slacrs
except ImportError:
    slacrs = None

from angrmanagement.logic.threads import gui_thread_schedule_async

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class ChessTarget:
    """
    Models a CHESS challenge target.
    """
    def __init__(self, description: str, target_id: str, challenge_name: str, image_id: str):
        self.description = description
        self.target_id = target_id
        self.challenge_name = challenge_name
        self.image_id = image_id


class QTargetSelectorTableModel(QAbstractTableModel):
    """
    Implements a table model for targets.
    """

    Headers = ["Description", "Challenge", "Image ID"]
    COL_DESCRIPTION = 0
    COL_CHALLENGE = 1
    COL_IMAGEID = 2

    def __init__(self):
        super().__init__()
        self._targets: List[ChessTarget] = [ ]

    @property
    def targets(self):
        return self._targets

    @targets.setter
    def targets(self, v):
        self.beginResetModel()
        self._targets = v
        self.endResetModel()

    def rowCount(self, parent:PySide2.QtCore.QModelIndex=...) -> int:
        return len(self.targets)

    def columnCount(self, parent:PySide2.QtCore.QModelIndex=...) -> int:
        return len(self.Headers)

    def headerData(self, section:int, orientation:PySide2.QtCore.Qt.Orientation, role:int=...) -> typing.Any:
        if role != Qt.DisplayRole:
            return None

        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index:PySide2.QtCore.QModelIndex, role:int=...) -> typing.Any:
        if not index.isValid():
            return None
        row = index.row()
        if row >= len(self.targets):
            return None
        target = self.targets[row]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._get_column_text(target, col)

        return None

    @staticmethod
    def _get_column_text(target: ChessTarget, col: int) -> str:
        mapping = {
            QTargetSelectorTableModel.COL_DESCRIPTION: QTargetSelectorTableModel._get_description,
            QTargetSelectorTableModel.COL_CHALLENGE: QTargetSelectorTableModel._get_challenge_name,
            QTargetSelectorTableModel.COL_IMAGEID: QTargetSelectorTableModel._get_image_id,
        }
        return mapping[col](target)

    @staticmethod
    def _get_description(target: ChessTarget) -> str:
        return target.description

    @staticmethod
    def _get_challenge_name(target: ChessTarget) -> str:
        return target.challenge_name

    @staticmethod
    def _get_image_id(target: ChessTarget) -> str:
        return target.image_id


class QTargetSelectorTableView(QTableView):
    """
    Implements a table view for targets.
    """
    def __init__(self):
        super().__init__()

        self.horizontalHeader().setVisible(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        self.model: QTargetSelectorTableModel = QTargetSelectorTableModel()
        self.setModel(self.model)


class QTargetSelectorDialog(QDialog):
    """
    Implements a CHESS target selector dialog.
    """
    def __init__(self, workspace: 'Workspace', parent=None):
        super().__init__(parent)

        if slacrs is None:
            QMessageBox.Critical(self,
                                 "Slacrs is not installed",
                                 "Cannot import slacrs. Please make sure slacrs is properly installed.",
                                 QMessageBox.Ok)
            self.close()
            return

        self.workspace = workspace
        self.target_id: Optional[str] = None
        self.target_image_id: Optional[str] = None
        self.target_description: Optional[str] = None
        self.ok: bool = False
        self.setMinimumWidth(400)

        self._status_label: QLabel = None
        self._table: QTargetSelectorTableView = None
        self._ok_button: QPushButton = None
        self._cancel_button: QPushButton = None

        self._init_widgets()

        self._status_label.setText("Loading...")
        self.workspace.main_window.app.processEvents()
        th = threading.Thread(target=self._load_targets, daemon=True)
        th.start()

    def _init_widgets(self):

        # table
        self._table = QTargetSelectorTableView()

        # status
        status_lbl = QLabel("Status:")
        self._status_label = QLabel()
        status_layout = QHBoxLayout()
        status_layout.addWidget(status_lbl)
        status_layout.addWidget(self._status_label)
        status_layout.addStretch(0)

        # buttons
        self._ok_button = QPushButton("Ok")
        self._ok_button.clicked.connect(self._on_ok_button_clicked)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self._on_cancel_button_clicked)
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self._ok_button)
        buttons_layout.addWidget(self._cancel_button)

        layout = QVBoxLayout()
        layout.addWidget(self._table)
        layout.addLayout(status_layout)
        layout.addLayout(buttons_layout)
        self.setLayout(layout)

    def _load_targets(self):
        from slacrs.model import Target, Challenge  # pylint:disable=import-outside-toplevel,import-error
        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())

        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            # chess connector does not exist
            return
        slacrs_instance = connector.slacrs_instance()
        if slacrs_instance is None:
            # slacrs does not exist. continue
            return
        session = slacrs_instance.session()
        db_targets = session.query(Target)
        targets: List[ChessTarget] = [ ]

        for db_target in db_targets:
            db_challenge = session.query(Challenge).filter(
                Challenge.id == db_target.challenge_id
            ).first()
            t = ChessTarget(db_target.description, db_target.id, db_challenge.name, db_target.images[0].id)
            targets.append(t)

        session.close()
        gui_thread_schedule_async(self._update_table, args=(targets,))

    def _update_table(self, targets):
        self._table.model.targets = targets
        self._table.viewport().update()
        self._status_label.setText("Ready.")

    #
    # Events
    #

    def _on_ok_button_clicked(self):

        selection_model = self._table.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(self,
                                "No target is selected",
                                "Please select a CHESS target to continue.",
                                QMessageBox.Ok)
            return

        rows = selection_model.selectedRows()
        target = self._table.model.targets[rows[0].row()]

        self.target_id = target.target_id
        self.target_description = target.description
        self.target_image_id = target.image_id
        self.ok = True
        self.close()

    def _on_cancel_button_clicked(self):
        self.target_id = None
        self.target_description = None
        self.ok = False
        self.close()
