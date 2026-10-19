from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFrame, QHeaderView, QSizePolicy, QTableWidget, QTableWidgetItem, QVBoxLayout

from angrmanagement.present.symexec import CONSTRAINT_COLUMNS, constraint_rows

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class QConstraintViewer(QFrame):
    """
    `QConstraintViewer` in `StateInspector`
    """

    COLUMNS = CONSTRAINT_COLUMNS

    def __init__(self, state, parent, workspace: Workspace) -> None:
        super().__init__(parent)

        self._state = state
        self.workspace = workspace

        self.table = None

        self._state.am_subscribe(self._watch_state)

    #
    # Public methods
    #

    def reload(self) -> None:
        if self._state.am_none:
            return

        self.table.setRowCount(0)
        for cells in constraint_rows(self._state):
            count = self.table.rowCount()
            self.table.insertRow(count)
            for col, text in enumerate(cells):
                self.table.setItem(count, col, QTableWidgetItem(text))

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        if self._state.am_none:
            return

        layout = QVBoxLayout()

        table = QTableWidget(self)
        table.setColumnCount(len(self.COLUMNS))
        table.setHorizontalHeaderLabels(self.COLUMNS)
        table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        self.table = table
        layout.addWidget(table)

        self.setLayout(layout)

    def _watch_state(self, **kwargs) -> None:  # pylint: disable=unused-argument
        if self.table is None:
            self._init_widgets()
        self.reload()
