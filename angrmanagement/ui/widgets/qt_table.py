"""
Qt models over the tables of angrmanagement.present.tables.

:class:`QtTableModelAdapter` is a ``QAbstractTableModel`` that shows a ``TableModel``: the cell text, check boxes and
editable cells, the tabular font from the configuration, and colours from the cell's style key through the current
theme. It forwards sorting to the model and turns the model's change notifications into Qt's.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QBrush, QColor

from angrmanagement.config import Conf
from angrmanagement.present.tables import APPENDED, DATA, LAYOUT, RESET
from angrmanagement.present.theme import StyleSpec, Theme

if TYPE_CHECKING:
    from angrmanagement.config.color import Color
    from angrmanagement.present.tables import Cell, TableModel

_ALIGNMENTS = {
    "right": Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
    "center": Qt.AlignmentFlag.AlignCenter,
}


def _qcolor(color: Color | None) -> QColor | None:
    if color is None:
        return None
    return QColor(color.r, color.g, color.b, color.a)


class QtTableModelAdapter(QAbstractTableModel):
    """
    A Qt table model that shows a :class:`~angrmanagement.present.tables.TableModel`.

    :param table_model:     The model to show.
    :param use_table_font:  Whether cells use the configuration's tabular view font.
    """

    def __init__(self, table_model: TableModel, parent=None, use_table_font: bool = True) -> None:
        super().__init__(parent)
        self.table_model = table_model
        self.use_table_font = use_table_font
        # (row, col) -> Cell, so that the roles of one cell are computed once per change
        self._data_cache: dict[tuple[int, int], Cell] = {}
        self._theme: Theme | None = None
        table_model.about_to_change.connect(self._on_about_to_change)
        table_model.changed.connect(self._on_changed)

    #
    # Caches
    #

    def clear_data_cache(self) -> None:
        """Forget the cells and colours computed so far, for example after the palette changed."""
        self._data_cache = {}
        self._theme = None

    @property
    def theme(self) -> Theme:
        if self._theme is None:
            self._theme = Theme.from_conf()
        return self._theme

    def cell_at(self, row: int, col: int) -> Cell:
        key = (row, col)
        cell = self._data_cache.get(key)
        if cell is None:
            cell = self.table_model.cell(row, col)
            self._data_cache[key] = cell
        return cell

    def style_of(self, cell: Cell) -> StyleSpec:
        style = self.theme.style(cell.style_key) if cell.style_key else StyleSpec()
        if cell.style is not None:
            style = style.merged(cell.style)
        return style

    #
    # QAbstractTableModel
    #

    def rowCount(self, parent=None) -> int:  # pylint:disable=unused-argument
        return self.table_model.row_count

    def columnCount(self, parent=None) -> int:  # pylint:disable=unused-argument
        return len(self.table_model.columns)

    def headerData(self, section, orientation, role=None) -> Any:
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            columns = self.table_model.columns
            if 0 <= section < len(columns):
                return columns[section].name
        elif role == Qt.ItemDataRole.InitialSortOrderRole:
            return Qt.SortOrder.AscendingOrder
        return None

    def data(self, index, role=None) -> Any:
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if not 0 <= row < self.table_model.row_count:
            return None
        columns = self.table_model.columns
        if not 0 <= col < len(columns):
            return None
        column = columns[col]

        if role == Qt.ItemDataRole.FontRole:
            return Conf.tabular_view_font if self.use_table_font else None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return _ALIGNMENTS.get(column.align)

        cell = self.cell_at(row, col)
        if role == Qt.ItemDataRole.DisplayRole:
            return None if column.checkable else cell.text
        if role == Qt.ItemDataRole.EditRole:
            return cell.text
        if role == Qt.ItemDataRole.CheckStateRole:
            if not column.checkable:
                return None
            return Qt.CheckState.Checked if cell.checked else Qt.CheckState.Unchecked
        if role == Qt.ItemDataRole.ToolTipRole:
            return cell.tooltip
        if role == Qt.ItemDataRole.ForegroundRole:
            fg = _qcolor(self.style_of(cell).fg)
            return QBrush(fg) if fg is not None else None
        if role == Qt.ItemDataRole.BackgroundRole:
            return _qcolor(self.style_of(cell).bg)
        return None

    def flags(self, index: QModelIndex | QPersistentModelIndex) -> Qt.ItemFlag:
        flags = super().flags(index)
        columns = self.table_model.columns
        if index.isValid() and 0 <= index.column() < len(columns):
            column = columns[index.column()]
            if column.checkable:
                flags |= Qt.ItemFlag.ItemIsUserCheckable
            if column.editable:
                flags |= Qt.ItemFlag.ItemIsEditable
        return flags

    def setData(self, index, value, role: Any = Qt.ItemDataRole.EditRole) -> bool:
        if not index.isValid():
            return False
        row, col = index.row(), index.column()
        if role == Qt.ItemDataRole.CheckStateRole:
            accepted = self.table_model.set_checked(row, col, Qt.CheckState(value) == Qt.CheckState.Checked)
        elif role == Qt.ItemDataRole.EditRole:
            accepted = self.table_model.set_text(row, col, str(value))
        else:
            return False
        if accepted:
            self._data_cache.pop((row, col), None)
            self.dataChanged.emit(index, index, [role])
        return accepted

    def sort(self, column, order=None) -> None:
        self.table_model.sort(column, order == Qt.SortOrder.DescendingOrder)

    #
    # Change notifications from the model
    #

    def _on_about_to_change(self, kind: str, first: int, last: int) -> None:
        if kind == RESET:
            self.beginResetModel()
        elif kind == LAYOUT:
            self.layoutAboutToBeChanged.emit()
        elif kind == APPENDED:
            self.beginInsertRows(QModelIndex(), first, last)

    def _on_changed(self, kind: str, first: int, last: int) -> None:
        self._data_cache = {}
        if kind == RESET:
            self.endResetModel()
        elif kind == LAYOUT:
            self.layoutChanged.emit()
        elif kind == APPENDED:
            self.endInsertRows()
        elif kind == DATA:
            self.dataChanged.emit(self.index(first, 0), self.index(last, max(self.columnCount() - 1, 0)))
