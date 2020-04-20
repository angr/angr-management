from typing import Any

from PySide2.QtWidgets import QTableView, QTableWidgetItem, QAbstractItemView
from PySide2.QtGui import QColor
from PySide2.QtCore import Qt, QAbstractTableModel, QModelIndex

from angr.analyses.cfg.cfg_fast import MemoryData

from ...utils import filter_string_for_display
from ...config import Conf


class QStringModel(QAbstractTableModel):

    HEADER = [ "Address", "Length", "String" ]

    ADDRESS_COL = 0
    LENGTH_COL = 1
    STRING_COL = 2

    def __init__(self, cfg, func=None):
        super().__init__()

        self._cfg = cfg
        self._function = func
        self._xrefs = None

        self._values = None

    @property
    def cfg(self):
        return self._cfg

    @cfg.setter
    def cfg(self, v):
        self.beginResetModel()
        self._cfg = v
        self._values = None
        self.endResetModel()

    @property
    def xrefs(self):
        return self._xrefs

    @xrefs.setter
    def xrefs(self, v):
        self._xrefs = v
        self._values = None

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v):
        self._function = v
        self._values = None

    def _get_all_string_memory_data(self):
        lst = [ ]
        if self.cfg is None:
            return lst
        for v in self.cfg.memory_data.values():
            if v.sort == 'string':
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

    def __len__(self):
        return self.rowCount()

    def rowCount(self, parent=None) -> int:
        return len(self.values)

    def columnCount(self, parent=None) -> int:
        return len(self.HEADER)

    def headerData(self, section, orientation, role=None) -> Any:
        if role == Qt.DisplayRole:
            if section < len(self.HEADER):
                return self.HEADER[section]
        elif role == Qt.InitialSortOrderRole:
            return Qt.AscendingOrder

        return None

    def data(self, index, role=None) -> Any:
        if not index.isValid():
            return None

        row = index.row()
        if row >= len(self.values):
            return None

        col = index.column()
        v = self.values[row]

        if role == Qt.DisplayRole:
            return self._get_column_text(v, col)
        elif role == Qt.FontRole:
            return Conf.tabular_view_font
        return None

    def sort(self, column, order=None) -> Any:
        self.layoutAboutToBeChanged.emit()

        self._values = sorted(
            self.values,
            key=lambda x: self._get_column_data(x, column), reverse=order == Qt.DescendingOrder,
        )
        self.layoutChanged.emit()

    def _get_column_text(self, v: MemoryData, col: int):
        if col < len(self.HEADER):
            data = self._get_column_data(v, col)
            if col == self.ADDRESS_COL and type(data) is int:
                return hex(data)
            return data

    def _get_column_data(self, v: MemoryData, col: int) -> Any:
        mapping = {
            self.ADDRESS_COL: lambda x: x.addr,
            self.LENGTH_COL: lambda x: x.size,
            self.STRING_COL: lambda x: filter_string_for_display(x.content.decode("utf-8")) if x.content is not None else "<ERROR>",
        }

        if col in mapping:
            return mapping[col](v)
        return None


class QStringTable(QTableView):
    def __init__(self, parent, selection_callback=None):
        super(QStringTable, self).__init__(parent)

        self._selected = selection_callback

        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setHorizontalScrollMode(self.ScrollPerPixel)

        self._model = QStringModel(None)
        self.setModel(self._model)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.doubleClicked.connect(self._on_string_selected)

    #
    # Properties
    #

    @property
    def cfg(self):
        return self._model.cfg

    @cfg.setter
    def cfg(self, v):
        self._model.cfg = v
        self.fast_resize()

    @property
    def xrefs(self):
        return self._model.xrefs

    @xrefs.setter
    def xrefs(self, v):
        self._model.xrefs = v

    @property
    def function(self):
        return self._model.function

    @function.setter
    def function(self, v):
        self._model.function = v
        self.fast_resize()

    #
    # Public methods
    #

    def fast_resize(self):

        self.setVisible(False)
        self.resizeColumnsToContents()
        self.setVisible(True)

    #
    # Event handlers
    #

    def _on_string_selected(self, model_index):
        selected_index = model_index.row()
        if self._model is None:
            return
        if 0 <= selected_index < len(self._model.values):
            selected_item = self._model.values[selected_index]
        else:
            selected_item = None

        if self._selected is not None:
            self._selected(selected_item)
