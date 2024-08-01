from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QSortFilterProxyModel, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.config import Conf
from angrmanagement.ui.dialogs.xref import XRefDialog

if TYPE_CHECKING:
    from angr.analyses.cfg.cfg_fast import MemoryData
    from PySide6.QtGui import QKeyEvent

    from angrmanagement.data.instance import Instance

    from .search_view import SearchView


@dataclass
class SearchItem:
    """
    Describes each item in QSearchModel.
    """

    addr: int
    search_value: int | float | bytes
    search_value_as_bytes: bytes


class QSearchModel(QAbstractTableModel):
    """
    The model for the table.
    """

    HEADER = ["Address", "Value"]

    ADDRESS_COL = 0
    VALUE_COL = 1

    def __init__(self, cfg, values=None) -> None:
        super().__init__()

        self._cfg = cfg
        self._values = values

    @property
    def values(self):
        return self._values if self._values else []

    @values.setter
    def values(self, values) -> None:
        self._values = values

    def __len__(self) -> int:
        return self.rowCount()

    def rowCount(self, parent=None) -> int:  # pylint: disable=unused-argument
        return len(self.values)

    def columnCount(self, parent=None) -> int:  # pylint: disable=unused-argument
        return len(self.HEADER)

    def headerData(
        self, section, orientation, role=None  # pylint: disable=unused-argument
    ) -> Qt.SortOrder | str | None:
        if role == Qt.ItemDataRole.DisplayRole:
            if section < len(self.HEADER):
                return self.HEADER[section]
        elif role == Qt.ItemDataRole.InitialSortOrderRole:
            return Qt.SortOrder.AscendingOrder

        return None

    def data(self, index, role=None) -> Any:
        if not index.isValid():
            return None

        row = index.row()
        if row >= len(self.values):
            return None

        col = index.column()
        v = self.values[row]

        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_column_text(v, col)
        elif role == Qt.ItemDataRole.FontRole:
            return Conf.tabular_view_font
        return None

    def sort(self, column, order=None) -> Any:
        self.layoutAboutToBeChanged.emit()

        self._values = sorted(
            self.values,
            key=lambda x: self._get_column_data(x, column),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )
        self.layoutChanged.emit()

    def _get_column_text(self, v: MemoryData, col: int):
        if col < len(self.HEADER):
            data = self._get_column_data(v, col)
            if col == self.ADDRESS_COL and isinstance(data, int):
                return f"{data:x}"
            return data
        return ""

    def _get_column_data(self, v: SearchItem, col: int) -> Any:
        mapping = {
            self.ADDRESS_COL: lambda x: x.addr,
            self.VALUE_COL: lambda x: x.search_value,
        }

        if col in mapping:
            return mapping[col](v)
        return None


class QSearchTable(QTableView):
    """
    The value search table widget.
    """

    def __init__(self, instance: Instance, parent, selection_callback=None) -> None:
        super().__init__(parent)
        self._parent: SearchView = parent

        self._instance = instance
        self._selected = selection_callback
        self._filter = None

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self._model = QSearchModel(None)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setModel(self._proxy)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        # let the last column (string) fill table width
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        self.doubleClicked.connect(self._on_string_selected)

    #
    # Properties
    #

    @property
    def filter_string(self):
        return self._filter

    @filter_string.setter
    def filter_string(self, v) -> None:
        self._filter = v
        found_values, beastr = self._parent.plugin.on_search_trigger(
            self._filter, self._parent._selected_type, self._parent.alignment, self._parent.should_search_code
        )
        values = [SearchItem(addr, v, beastr) for addr in found_values]
        self._model.layoutAboutToBeChanged.emit()
        self._model.values = values
        self._model.layoutChanged.emit()

    #
    # Public methods
    #

    def fast_resize(self) -> None:
        self.setVisible(False)
        self.resizeColumnsToContents()
        self.setVisible(True)

    #
    # Event handlers
    #

    def _on_string_selected(self, model_index) -> None:
        model_index = self._proxy.mapToSource(model_index)
        selected_index = model_index.row()
        if self._model is None:
            return
        selected_item = self._model.values[selected_index] if 0 <= selected_index < len(self._model.values) else None

        if self._selected is not None:
            self._selected(selected_item)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_X:
            # xrefs
            if self._model is None:
                return

            selected_rows = list(self.selectionModel().selectedRows())
            if len(selected_rows) == 1:
                model_index = self._proxy.mapToSource(selected_rows[0])
                selected_index = model_index.row()
                if 0 <= selected_index < len(self._model.values):
                    selected_item: SearchItem = self._model.values[selected_index]
                    dialog = XRefDialog(
                        addr=selected_item.addr,
                        dst_addr=selected_item.addr,
                        xrefs_manager=self._instance.project.kb.xrefs,
                        instance=self._instance,
                        parent=self,
                        disassembly_view=self._parent.workspace.view_manager.first_view_in_category("disassembly"),
                    )
                    dialog.exec_()
            return

        super().keyPressEvent(event)
