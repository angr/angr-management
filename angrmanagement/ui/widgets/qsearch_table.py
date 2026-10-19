from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QHeaderView

from angrmanagement.present.search import SearchResultsModel
from angrmanagement.ui.widgets.qfast_table_view import QFastTableView
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    from collections.abc import Sequence

    import PySide6

    from angrmanagement.data.search import SearchResult


class QSearchTableModel(QtTableModelAdapter):
    """
    Qt model over a :class:`~angrmanagement.present.search.SearchResultsModel`, which holds the rows, the sorting and
    the filtering.
    """

    HEADER = SearchResultsModel.HEADER

    ADDRESS_COL = SearchResultsModel.ADDRESS_COL
    KIND_COL = SearchResultsModel.KIND_COL
    FUNCTION_COL = SearchResultsModel.FUNCTION_COL
    MATCH_COL = SearchResultsModel.MATCH_COL
    CONTEXT_COL = SearchResultsModel.CONTEXT_COL

    table_model: SearchResultsModel

    def __init__(self, results_model: SearchResultsModel | None = None) -> None:
        super().__init__(results_model if results_model is not None else SearchResultsModel())

    #
    # Properties
    #

    @property
    def results(self) -> list[SearchResult]:
        return self.table_model.results

    @property
    def total_count(self) -> int:
        return self.table_model.total_count

    def set_results(self, results: Sequence[SearchResult]) -> None:
        self.table_model.set_results(results)

    def clear(self) -> None:
        self.set_results([])

    def filter(self, keyword: str) -> None:
        self.table_model.filter(keyword)

    def result_at(self, row: int) -> SearchResult | None:
        return self.table_model.result_at(row)

    @staticmethod
    def _column_text(result: SearchResult, col: int) -> str:
        return SearchResultsModel.result_column_text(result, col)


class QSearchTable(QFastTableView):
    """Lazily-rendered, sortable, and filterable table of search results."""

    def __init__(self, parent, view, results_model: SearchResultsModel | None = None) -> None:
        header = QHeaderView(Qt.Orientation.Horizontal)
        super().__init__(parent, header=header)
        self._view = view

        header.setSectionsClickable(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        self.set_row_height(22)

        self._model = QSearchTableModel(results_model)
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
        menu = self.model_.table_model.context_menu(self.selected_rows())
        if menu is None:
            return
        menu.qmenu(cached=False).exec_(QCursor.pos())
