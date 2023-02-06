# pylint:disable=unused-argument
import asyncio
import threading
import typing
from typing import TYPE_CHECKING, List, Optional, Tuple

from PySide6.QtCore import QAbstractTableModel, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
)
from tornado.platform.asyncio import AnyThreadEventLoopPolicy

from angrmanagement.logic.threads import gui_thread_schedule_async

if TYPE_CHECKING:
    import PySide6

    from angrmanagement.ui.workspace import Workspace

try:
    import slacrs
except ImportError:
    slacrs = None


class TraceDescriptor:
    """
    Models a trace.
    """

    def __init__(self, trace_id: str, input_id: str, created_at, type_: str):
        self.trace_id = trace_id
        self.input_id = input_id
        self.created_at = created_at
        self.type = type_


class QTraceTableModel(QAbstractTableModel):
    """
    Implements a table model for traces.
    """

    Headers = ["Trace ID", "Created at", "Input ID", "Input Length", "Type"]
    COL_TRACEID = 0
    COL_CREATEDAT = 1
    COL_INPUTID = 2
    COL_INPUTLENGTH = 3
    COL_TYPE = 4

    def __init__(self):
        super().__init__()
        self._traces: List[TraceDescriptor] = []

    @property
    def traces(self):
        return self._traces

    @traces.setter
    def traces(self, v):
        self.beginResetModel()
        self._traces = v
        self.endResetModel()

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:
        return len(self.traces)

    def columnCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:
        return len(self.Headers)

    def headerData(self, section: int, orientation: PySide6.QtCore.Qt.Orientation, role: int = ...) -> typing.Any:
        if role != Qt.DisplayRole:
            return None

        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index: PySide6.QtCore.QModelIndex, role: int = ...) -> typing.Any:
        if not index.isValid():
            return None
        row = index.row()
        if row >= len(self.traces):
            return None
        trace = self.traces[row]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._get_column_text(trace, col)

        return None

    @staticmethod
    def _get_column_text(trace: TraceDescriptor, col: int) -> str:
        mapping = {
            QTraceTableModel.COL_TRACEID: QTraceTableModel._get_trace_id,
            QTraceTableModel.COL_CREATEDAT: QTraceTableModel._get_trace_created_at,
            QTraceTableModel.COL_TYPE: QTraceTableModel._get_trace_type,
            QTraceTableModel.COL_INPUTID: QTraceTableModel._get_trace_input_id,
            QTraceTableModel.COL_INPUTLENGTH: lambda x: "Unknown",
        }
        return mapping[col](trace)

    @staticmethod
    def _get_trace_id(trace: TraceDescriptor) -> str:
        return trace.trace_id

    @staticmethod
    def _get_trace_created_at(trace: TraceDescriptor) -> str:
        return trace.created_at

    @staticmethod
    def _get_trace_type(trace: TraceDescriptor) -> str:
        return trace.type

    @staticmethod
    def _get_trace_input_id(trace: TraceDescriptor) -> str:
        return trace.input_id


class QTraceTableView(QTableView):
    """
    Implements a trace view for CHESS traces.
    """

    def __init__(self):
        super().__init__()

        self.horizontalHeader().setVisible(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.MultiSelection)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        self.model: QTraceTableModel = QTraceTableModel()
        self.setModel(self.model)


class QChessTraceListDialog(QDialog):
    """
    Implements a CHESS trace list dialog.
    """

    def __init__(self, workspace: "Workspace", parent=None):
        super().__init__(parent)

        if slacrs is None:
            QMessageBox.Critical(
                self,
                "Slacrs is not installed",
                "Cannot import slacrs. Please make sure slacrs is properly installed.",
                QMessageBox.Ok,
            )
            self.close()
            return

        self.workspace = workspace
        self.trace_ids: Optional[List[Tuple[str, str]]] = None  # input ID, trace ID
        self.setMinimumWidth(400)

        self._status_label: QLabel = None
        self._table: QTraceTableView = None
        self._ok_button: QPushButton = None
        self._cancel_button: QPushButton = None

        self.setWindowTitle("Open traces from CHECRS")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self._init_widgets()

        self._status_label.setText("Loading...")
        self.workspace.main_window.app.processEvents()
        th = threading.Thread(target=self._load_traces, daemon=True)
        th.start()

    def _init_widgets(self):
        # table
        self._table = QTraceTableView()

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

    def _load_traces(self):
        from slacrs.model import Input, Trace  # pylint:disable=import-outside-toplevel,import-error

        asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())

        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            return

        connector = self.workspace.plugins.get_plugin_instance_by_name("ChessConnector")
        if connector is None:
            # chess connector does not exist
            return
        slacrs_instance = connector.slacrs_instance()
        if slacrs_instance is None:
            # slacrs does not exist. continue
            return

        session = slacrs_instance.session()
        target_image_id = connector.target_image_id
        if not target_image_id:
            return

        traces: List[TraceDescriptor] = []

        db_traces = session.query(Trace).join(Trace.input).filter(Input.target_image_id == target_image_id)
        for db_trace in db_traces:
            db_trace: Trace
            t = TraceDescriptor(db_trace.id, db_trace.input_id, db_trace.created_at, "block trace")
            traces.append(t)

        session.close()
        gui_thread_schedule_async(self._update_table, args=(traces,))

    def _update_table(self, traces):
        self._table.model.traces = traces
        self._table.viewport().update()
        self._status_label.setText("Ready.")

    #
    # Events
    #

    def _on_ok_button_clicked(self):
        selection_model = self._table.selectionModel()
        if not selection_model.hasSelection():
            QMessageBox.warning(
                self, "No target is selected", "Please select a CHESS target to continue.", QMessageBox.Ok
            )
            return

        rows = selection_model.selectedRows()
        self.trace_ids = []
        for row in rows:
            trace = self._table.model.traces[row.row()]
            self.trace_ids.append((trace.input_id, trace.trace_id))
        self.close()

    def _on_cancel_button_clicked(self):
        self.close()
