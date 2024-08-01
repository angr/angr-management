from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from PySide6.QtCore import QAbstractTableModel, QSortFilterProxyModel, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.config import Conf
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.utils import filter_string_for_display

if TYPE_CHECKING:
    from angr.analyses.cfg.cfg_fast import MemoryData
    from PySide6.QtGui import QKeyEvent

    from angrmanagement.data.instance import Instance


class QStringModel(QAbstractTableModel):
    HEADER = ["Address", "Size (Bytes)", "Length", "String"]

    ADDRESS_COL = 0
    SIZE_COL = 1
    LENGTH_COL = 2
    STRING_COL = 3

    def __init__(self, cfg, func=None) -> None:
        super().__init__()

        self._cfg = cfg
        self._function = func
        self._xrefs = None

        self._values = None

    @property
    def cfg(self):
        return self._cfg

    @cfg.setter
    def cfg(self, v) -> None:
        self.beginResetModel()
        self._cfg = v
        self._values = None
        self.endResetModel()

    @property
    def xrefs(self):
        return self._xrefs

    @xrefs.setter
    def xrefs(self, v) -> None:
        self.beginResetModel()
        self._xrefs = v
        self._values = None
        self.endResetModel()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v) -> None:
        self.beginResetModel()
        self._function = v
        self._values = None
        self.endResetModel()

    def _get_all_string_memory_data(self):
        lst = []
        if self.cfg is None:
            return lst
        for v in self.cfg.memory_data.values():
            if v.sort in {MemoryDataSort.String, MemoryDataSort.UnicodeString}:
                if self._function is None:
                    lst.append(v)
                else:
                    xrefs = self._xrefs
                    if v.addr in xrefs.xrefs_by_dst:
                        for xref in xrefs.xrefs_by_dst[v.addr]:
                            if xref.block_addr in self._function.block_addrs_set:
                                lst.append(v)
                                break
        return lst

    @property
    def values(self):
        if self._values is None:
            self._values = self._get_all_string_memory_data()
        return self._values

    def __len__(self) -> int:
        return self.rowCount()

    def rowCount(self, parent=None) -> int:  # pylint: disable=unused-argument
        return len(self.values)

    def columnCount(self, parent=None) -> int:  # pylint: disable=unused-argument
        return len(self.HEADER)

    def headerData(self, section, orientation, role=None) -> Any:  # pylint: disable=unused-argument
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

    @staticmethod
    def _get_decoded_string_content(md: MemoryData) -> str:
        sort_to_encoding = {MemoryDataSort.String: "utf-8", MemoryDataSort.UnicodeString: "utf_16_le"}
        return md.content.decode(sort_to_encoding[md.sort])

    def _get_column_data(self, v: MemoryData, col: int) -> Any:
        mapping = {
            self.ADDRESS_COL: lambda x: x.addr,
            self.SIZE_COL: lambda x: x.size,
            self.LENGTH_COL: lambda x: len(self._get_decoded_string_content(x)) if x.content is not None else "<ERROR>",
            self.STRING_COL: lambda x: (
                filter_string_for_display(self._get_decoded_string_content(x)) if x.content is not None else "<ERROR>"
            ),
        }

        if col in mapping:
            return mapping[col](v)
        return None


class QStringTable(QTableView):
    def __init__(self, instance: Instance, parent, selection_callback=None) -> None:
        super().__init__(parent)

        self._instance = instance
        self._selected = selection_callback
        self._filter = None

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self._model = QStringModel(None)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setModel(self._proxy)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        # let the last column (string) fill table width
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.horizontalHeader().setSectionResizeMode(QStringModel.STRING_COL, QHeaderView.ResizeMode.Stretch)

        self.doubleClicked.connect(self._on_string_selected)

    #
    # Properties
    #

    @property
    def cfg(self):
        return self._model.cfg

    @cfg.setter
    def cfg(self, v) -> None:
        self._model.cfg = v
        self.fast_resize()

    @property
    def xrefs(self):
        return self._model.xrefs

    @xrefs.setter
    def xrefs(self, v) -> None:
        self._model.xrefs = v

    @property
    def function(self):
        return self._model.function

    @function.setter
    def function(self, v) -> None:
        self._model.function = v
        self.fast_resize()

    @property
    def filter_string(self):
        return self._filter

    @filter_string.setter
    def filter_string(self, v) -> None:
        self._filter = v
        if isinstance(v, re.Pattern):
            self._proxy.setFilterRegExp(self._filter.pattern)
        else:
            self._proxy.setFilterWildcard(self._filter)
        self._proxy.setFilterKeyColumn(2)

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
                    selected_item: MemoryData = self._model.values[selected_index]
                    dialog = XRefDialog(
                        addr=selected_item.addr,
                        dst_addr=selected_item.addr,
                        xrefs_manager=self.xrefs,
                        instance=self._instance,
                        parent=self,
                    )
                    dialog.exec_()
            return

        return super().keyPressEvent(event)
