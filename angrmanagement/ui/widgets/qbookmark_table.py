from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QTableView

from angrmanagement.config import Conf

if TYPE_CHECKING:
    import PySide6

    from angrmanagement.data.annotations import AnnotationManager, Bookmark
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QBookmarkTableModel(QAbstractTableModel):
    """
    Table model over the instance's bookmarks.
    """

    Headers = ["Address", "Function", "Label", "Added"]
    ADDRESS_COL = 0
    FUNCTION_COL = 1
    LABEL_COL = 2
    ADDED_COL = 3

    def __init__(self, instance: Instance) -> None:
        super().__init__()
        self.instance = instance
        self._bookmarks: list[Bookmark] = []
        self.reload()

    @property
    def annotations(self) -> AnnotationManager:
        return self.instance.annotations

    #
    # Public methods
    #

    def reload(self) -> None:
        self.beginResetModel()
        self._bookmarks = list(self.annotations.bookmarks)
        self.endResetModel()

    def bookmark_at(self, row: int) -> Bookmark | None:
        if 0 <= row < len(self._bookmarks):
            return self._bookmarks[row]
        return None

    #
    # QAbstractTableModel
    #

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self._bookmarks)

    def columnCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self.Headers)

    def headerData(self, section: int, orientation: PySide6.QtCore.Qt.Orientation, role: int = ...) -> Any:  # pylint:disable=unused-argument
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def flags(self, index: PySide6.QtCore.QModelIndex) -> Qt.ItemFlag:
        flags = super().flags(index)
        if index.column() == self.LABEL_COL:
            flags |= Qt.ItemFlag.ItemIsEditable
        return flags

    def data(self, index: PySide6.QtCore.QModelIndex, role: int = ...) -> Any:
        if not index.isValid():
            return None
        bookmark = self.bookmark_at(index.row())
        if bookmark is None:
            return None
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return self._get_column_text(bookmark, index.column())
        if role == Qt.ItemDataRole.FontRole:
            return Conf.tabular_view_font
        return None

    def setData(self, index: PySide6.QtCore.QModelIndex, value: Any, role: int = ...) -> bool:
        if not index.isValid() or role != Qt.ItemDataRole.EditRole or index.column() != self.LABEL_COL:
            return False
        bookmark = self.bookmark_at(index.row())
        if bookmark is None:
            return False
        self.annotations.set_bookmark_label(bookmark, str(value))
        self.dataChanged.emit(index, index)
        return True

    def sort(self, column: int, order=None) -> None:
        self.layoutAboutToBeChanged.emit()
        self._bookmarks = sorted(
            self._bookmarks,
            key=lambda b: self._get_column_data(b, column),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        self.layoutChanged.emit()

    #
    # Private methods
    #

    def _containing_function_name(self, addr: int) -> str:
        kb = self.instance.kb
        if kb is None:
            return ""
        func = kb.functions.floor_func(addr)
        if func is None or not (func.addr <= addr < func.addr + max(func.size, 1)):
            return ""
        return func.name

    def _get_column_data(self, bookmark: Bookmark, column: int) -> Any:
        if column == self.ADDRESS_COL:
            return bookmark.addr
        if column == self.FUNCTION_COL:
            return self._containing_function_name(bookmark.addr)
        if column == self.LABEL_COL:
            return bookmark.label
        if column == self.ADDED_COL:
            return bookmark.created_at
        return None

    def _get_column_text(self, bookmark: Bookmark, column: int) -> str:
        if column == self.ADDRESS_COL:
            return f"{bookmark.addr:#x}"
        if column == self.FUNCTION_COL:
            return self._containing_function_name(bookmark.addr)
        if column == self.LABEL_COL:
            return bookmark.label
        if column == self.ADDED_COL:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(bookmark.created_at))
        return ""


class QBookmarkTable(QTableView):
    """
    Bookmark table with an inline-editable label column.
    """

    def __init__(self, workspace: Workspace, instance: Instance, parent=None) -> None:
        super().__init__(parent)
        self.workspace = workspace
        self.instance = instance

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

        self._model = QBookmarkTableModel(instance)
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
        bookmarks = self.selected_bookmarks()
        menu = QMenu("", self)
        if bookmarks:
            menu.addAction("Go to", lambda: self.workspace.jump_to(bookmarks[0].addr))
            if len(bookmarks) == 1:
                menu.addAction("Rename label", self._edit_current_label)
            menu.addAction(
                "Delete" + ("" if len(bookmarks) == 1 else f" ({len(bookmarks)})"),
                lambda: self._delete(bookmarks),
            )
        menu.exec_(event.globalPos())

    def _on_cell_double_clicked(self, index) -> None:
        if index.column() == QBookmarkTableModel.LABEL_COL:
            return
        bookmark = self._model.bookmark_at(index.row())
        if bookmark is not None:
            self.workspace.jump_to(bookmark.addr)

    #
    # Private methods
    #

    def _edit_current_label(self) -> None:
        index = self.currentIndex()
        if index.isValid():
            self.edit(self._model.index(index.row(), QBookmarkTableModel.LABEL_COL))

    def _delete(self, bookmarks: list[Bookmark]) -> None:
        for bookmark in bookmarks:
            self.instance.annotations.remove_bookmark(bookmark)
