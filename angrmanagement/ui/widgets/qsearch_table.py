from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, Qt
from PySide6.QtGui import QAction, QCursor
from PySide6.QtWidgets import QHeaderView, QMenu

from angrmanagement.config import Conf
from angrmanagement.ui.widgets.qfast_table_view import QFastTableView

if TYPE_CHECKING:
    import PySide6

    from angrmanagement.data.search import SearchResult


class QSearchTableModel(QAbstractTableModel):
    """
    Table model over a list of :class:`SearchResult`. Rows are plain dataclasses and the view only
    paints what is visible, so a result set of tens of thousands of hits costs nothing to display.
    """

    HEADER = ["Address", "Kind", "Function", "Match", "Context"]

    ADDRESS_COL = 0
    KIND_COL = 1
    FUNCTION_COL = 2
    MATCH_COL = 3
    CONTEXT_COL = 4

    def __init__(self) -> None:
        super().__init__()
        self._all_results: list[SearchResult] = []
        self._results: list[SearchResult] = []
        self._filter: str = ""

    #
    # Properties
    #

    @property
    def results(self) -> list[SearchResult]:
        return self._results

    @property
    def total_count(self) -> int:
        return len(self._all_results)

    def set_results(self, results: list[SearchResult]) -> None:
        self.beginResetModel()
        self._all_results = results
        self._apply_filter()
        self.endResetModel()

    def clear(self) -> None:
        self.set_results([])

    def filter(self, keyword: str) -> None:
        self.layoutAboutToBeChanged.emit()
        self._filter = keyword
        self._apply_filter()
        self.layoutChanged.emit()

    def result_at(self, row: int) -> SearchResult | None:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    #
    # QAbstractTableModel
    #

    def rowCount(self, parent=None) -> int:  # pylint:disable=unused-argument
        return len(self._results)

    def columnCount(self, parent=None) -> int:  # pylint:disable=unused-argument
        return len(self.HEADER)

    def headerData(self, section, orientation, role=None) -> Any:  # pylint:disable=unused-argument
        if role == Qt.ItemDataRole.DisplayRole and section < len(self.HEADER):
            return self.HEADER[section]
        return None

    def data(self, index, role=None) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        if row >= len(self._results):
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._column_text(self._results[row], index.column())
        if role == Qt.ItemDataRole.FontRole:
            return Conf.tabular_view_font
        return None

    def sort(self, column, order=None) -> None:
        self.layoutAboutToBeChanged.emit()
        self._results = sorted(
            self._results,
            key=lambda r: self._column_key(r, column),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        self.layoutChanged.emit()

    #
    # Private methods
    #

    def _apply_filter(self) -> None:
        keyword = self._filter.lower()
        if not keyword:
            self._results = list(self._all_results)
            return
        self._results = [r for r in self._all_results if self._matches(r, keyword)]

    def _matches(self, result: SearchResult, keyword: str) -> bool:
        return any(keyword in self._column_text(result, col).lower() for col in range(len(self.HEADER)))

    @staticmethod
    def _column_key(result: SearchResult, col: int):
        if col == QSearchTableModel.ADDRESS_COL:
            return result.addr
        return QSearchTableModel._column_text(result, col)

    @staticmethod
    def _column_text(result: SearchResult, col: int) -> str:
        if col == QSearchTableModel.ADDRESS_COL:
            return f"{result.addr:#x}"
        if col == QSearchTableModel.KIND_COL:
            return result.kind
        if col == QSearchTableModel.FUNCTION_COL:
            return result.func_name or (f"{result.func_addr:#x}" if result.func_addr is not None else "")
        if col == QSearchTableModel.MATCH_COL:
            return result.text
        if col == QSearchTableModel.CONTEXT_COL:
            return result.context
        return ""


class QSearchTable(QFastTableView):
    """
    Lazily-rendered, sortable and filterable table of search results.
    """

    def __init__(self, parent, view) -> None:
        header = QHeaderView(Qt.Orientation.Horizontal)
        super().__init__(parent, header=header)
        self._view = view

        header.setSectionsClickable(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.set_row_height(22)

        self._model = QSearchTableModel()
        self.setModel(self._model)

        for idx, width in enumerate([120, 110, 160, 260]):
            header.resizeSection(idx, width)

        self.row_double_clicked.connect(self._on_row_activated)
        self.context_menu_requested.connect(self._on_context_menu_requested)

    #
    # Properties
    #

    @property
    def model_(self) -> QSearchTableModel:
        return self._model

    #
    # Public methods
    #

    def set_results(self, results: list[SearchResult]) -> None:
        self._model.set_results(results)
        self.viewport_update()

    def filter(self, keyword: str) -> None:
        self._model.filter(keyword)
        self.viewport_update()

    def selected_result(self) -> SearchResult | None:
        row = self.current_row
        return self._model.result_at(row) if row is not None else None

    def selected_results(self) -> list[SearchResult]:
        return [r for r in (self._model.result_at(row) for row in self.selected_rows()) if r is not None]

    #
    # Event handlers
    #

    def _on_row_activated(self, row: int) -> None:
        result = self._model.result_at(row)
        if result is not None:
            self._view.navigate_to_result(result)

    def _on_context_menu_requested(self, global_pos: PySide6.QtCore.QPoint) -> None:  # pylint:disable=unused-argument
        results = self.selected_results()
        if not results:
            return

        mnu = QMenu(self)
        for caption, handler in [
            ("Copy &address", self._view.copy_addresses),
            ("Copy &match", self._view.copy_matches),
            ("Copy &row", self._view.copy_rows),
        ]:
            act = QAction(caption, mnu)
            act.triggered.connect(lambda _checked=False, h=handler: h(self.selected_results()))
            mnu.addAction(act)
        mnu.addSeparator()
        for caption, category in [
            ("Jump in &disassembly", "disassembly"),
            ("Jump in &pseudocode", "pseudocode"),
            ("Jump in &hex view", "hex"),
        ]:
            act = QAction(caption, mnu)
            act.triggered.connect(
                lambda _checked=False, c=category: self._view.navigate_to_result(self.selected_result(), category=c)
            )
            mnu.addAction(act)
        mnu.exec_(QCursor.pos())
