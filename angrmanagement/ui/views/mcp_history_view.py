from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.mcp.history import MCPCallRecord
    from angrmanagement.ui.workspace import Workspace

_COLUMNS = ["Time", "Tool", "Arguments", "Status", "Duration (ms)"]


class MCPHistoryView(InstanceView):
    """
    Displays the history of MCP tool calls made by an AI agent against this session.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("mcp_history", workspace, default_docking_position, instance)

        self.base_caption = "MCP History"
        self._table: QTableWidget = None

        self._init_widgets()
        self._populate()
        self.workspace.mcp_history.am_subscribe(self._on_history_event)

    def closeEvent(self, event) -> None:
        self.workspace.mcp_history.am_unsubscribe(self._on_history_event)
        super().closeEvent(event)

    @staticmethod
    def minimumSizeHint():
        return QSize(0, 50)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._table = QTableWidget(self)
        self._table.setColumnCount(len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setWordWrap(False)
        header = self._table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Arguments column

        clear_button = QPushButton("Clear", self)
        clear_button.clicked.connect(self._on_clear_clicked)

        button_bar = QHBoxLayout()
        button_bar.setContentsMargins(0, 0, 0, 0)
        button_bar.addStretch(0)
        button_bar.addWidget(clear_button)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._table)
        layout.addLayout(button_bar)
        self.setLayout(layout)

    def _append_row(self, record: MCPCallRecord) -> None:
        row = self._table.rowCount()
        self._table.insertRow(row)

        time_item = QTableWidgetItem(record.timestamp.strftime("%H:%M:%S"))
        tool_item = QTableWidgetItem(record.tool)
        args_item = QTableWidgetItem(record.arguments_summary)
        args_item.setToolTip(record.arguments_summary)
        status_item = QTableWidgetItem(record.status)
        if record.status == "error":
            status_item.setForeground(QColor(0xC0, 0x00, 0x00))
            if record.error:
                status_item.setToolTip(record.error)
        duration_item = QTableWidgetItem(f"{record.duration_ms:.0f}")
        duration_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        for col, item in enumerate((time_item, tool_item, args_item, status_item, duration_item)):
            self._table.setItem(row, col, item)

        self._table.scrollToBottom()

    def _populate(self) -> None:
        self._table.setRowCount(0)
        for record in list(self.workspace.mcp_history.am_obj or []):
            self._append_row(record)

    def _on_history_event(self, added: MCPCallRecord | None = None, **kwargs) -> None:  # pylint:disable=unused-argument
        # invoked on the GUI thread; the MCP server marshals its events here
        if added is not None:
            self._append_row(added)
        else:
            self._populate()

    def _on_clear_clicked(self) -> None:
        self.workspace.mcp_history.am_obj = []
        self.workspace.mcp_history.am_event()
