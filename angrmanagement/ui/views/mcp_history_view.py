from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from angrmanagement.present.mcp_history import MCPHistoryPresenter, MCPHistoryTableModel
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

_COLUMNS = MCPHistoryTableModel.HEADER


class QMCPHistoryTable(QTableView):
    """The table of MCP calls; ``rowCount()`` is there for code written against the former QTableWidget."""

    def rowCount(self) -> int:
        model = self.model()
        return model.rowCount() if model is not None else 0


class MCPHistoryView(InstanceView):
    """
    Displays the history of MCP tool calls made by an AI agent against this session.
    """

    presenter: MCPHistoryPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "mcp_history",
            workspace,
            default_docking_position,
            instance,
            MCPHistoryPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "MCP History"
        self._table: QMCPHistoryTable

        self._init_widgets()
        self.presenter.model.changed.connect(self._on_model_changed)

    def closeEvent(self, event) -> None:
        self.presenter.model.changed.disconnect(self._on_model_changed)
        self.presenter.close()
        super().closeEvent(event)

    @staticmethod
    def minimumSizeHint():
        return QSize(0, 50)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._table = QMCPHistoryTable(self)
        self._table.setModel(QtTableModelAdapter(self.presenter.model, self._table, use_table_font=False))
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

    def _populate(self) -> None:
        self.presenter.populate()

    def _on_model_changed(self, *_args) -> None:
        self._table.scrollToBottom()

    def _on_clear_clicked(self) -> None:
        self.presenter.clear()
