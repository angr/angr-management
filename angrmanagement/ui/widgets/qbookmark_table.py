from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.present.bookmarks import BookmarksPresenter, BookmarksTableModel

from .qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    from angrmanagement.data.annotations import AnnotationManager, Bookmark
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QBookmarkTableModel(QtTableModelAdapter):
    """
    Qt model over a :class:`~angrmanagement.present.bookmarks.BookmarksTableModel`, the instance's bookmarks.
    """

    Headers = BookmarksTableModel.Headers
    ADDRESS_COL = BookmarksTableModel.ADDRESS_COL
    FUNCTION_COL = BookmarksTableModel.FUNCTION_COL
    LABEL_COL = BookmarksTableModel.LABEL_COL
    ADDED_COL = BookmarksTableModel.ADDED_COL

    table_model: BookmarksTableModel

    def __init__(self, instance: Instance, bookmarks_model: BookmarksTableModel | None = None) -> None:
        super().__init__(bookmarks_model if bookmarks_model is not None else BookmarksTableModel(instance))
        self.instance = instance

    @property
    def annotations(self) -> AnnotationManager:
        return self.instance.annotations

    def reload(self) -> None:
        self.table_model.reload()

    def bookmark_at(self, row: int) -> Bookmark | None:
        return self.table_model.bookmark_at(row)


class QBookmarkTable(QTableView):
    """
    Bookmark table with an inline-editable label column.
    """

    def __init__(
        self, workspace: Workspace, instance: Instance, parent=None, presenter: BookmarksPresenter | None = None
    ) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance
        self.presenter = presenter if presenter is not None else BookmarksPresenter(workspace, instance)

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(24)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setShowGrid(False)
        self.setSortingEnabled(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed)

        self._model = QBookmarkTableModel(instance, self.presenter.model)
        self.setModel(self._model)

        for col in range(len(QBookmarkTableModel.Headers)):
            hheader.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        hheader.resizeSection(QBookmarkTableModel.ADDRESS_COL, 110)
        hheader.resizeSection(QBookmarkTableModel.FUNCTION_COL, 150)
        hheader.resizeSection(QBookmarkTableModel.LABEL_COL, 220)
        hheader.setStretchLastSection(True)

        self.doubleClicked.connect(self._on_cell_double_clicked)

    #
    # Public methods
    #

    def reload(self) -> None:
        self._model.reload()

    def selected_bookmarks(self) -> list[Bookmark]:
        rows = {i.row() for i in self.selectedIndexes()}
        return [b for b in (self._model.bookmark_at(r) for r in sorted(rows)) if b is not None]

    #
    # Events
    #

    def contextMenuEvent(self, event) -> None:
        menu = self.presenter.bookmarks_menu(self.selected_bookmarks(), rename=lambda _b: self._edit_current_label())
        menu.qmenu(cached=False).exec_(event.globalPos())

    def _on_cell_double_clicked(self, index) -> None:
        if index.column() == QBookmarkTableModel.LABEL_COL:
            return
        self.presenter.model.activate(index.row())

    #
    # Private methods
    #

    def _edit_current_label(self) -> None:
        index = self.currentIndex()
        if index.isValid():
            self.edit(self._model.index(index.row(), QBookmarkTableModel.LABEL_COL))

    def _delete(self, bookmarks: list[Bookmark]) -> None:
        self.presenter.delete(bookmarks)
