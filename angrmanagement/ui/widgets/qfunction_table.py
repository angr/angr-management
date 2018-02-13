
import os

from PySide.QtGui import QTableView, QBrush, QColor, QAbstractItemView, QHeaderView, QTableWidgetItem
from PySide.QtCore import Qt, QSize, QAbstractTableModel, SIGNAL

from angr.misc import repr_addr


class QFunctionTableModel(QAbstractTableModel):

    Headers = ['Name', 'Address', 'Binary', 'Size', 'Blocks']
    NAME_COL = 0
    ADDRESS_COL = 1
    BINARY_COL = 2
    SIZE_COL = 3
    BLOCKS_COL = 4

    def __init__(self, func_list=None):

        super(QFunctionTableModel, self).__init__()

        self._func_list = func_list

    def __len__(self):
        if self._func_list is None:
            return 0
        return len(self._func_list)

    @property
    def func_list(self):
        return self._func_list

    @func_list.setter
    def func_list(self, v):
        self._func_list = v
        self.emit(SIGNAL("layoutChanged()"))

    def rowCount(self, *args, **kwargs):
        if self.func_list is None:
            return 0
        return len(self.func_list)

    def columnCount(self, *args, **kwargs):
        return len(self.Headers)

    def headerData(self, section, orientation, role):

        if role != Qt.DisplayRole:
            return None

        return self.Headers[section]

    def data(self, index, role):
        if not index.isValid():
            return None

        row = index.row()
        if row >= len(self):
            return None

        col = index.column()
        func = self.func_list[row]

        if role == Qt.DisplayRole:

            mapping = {
                self.NAME_COL:
                    lambda f: f.name,
                self.ADDRESS_COL:
                    lambda f: repr_addr(f.addr, x=False),
                self.BINARY_COL:
                    lambda f: self._get_binary_name(f),
                self.SIZE_COL:
                    lambda f: "%d" % f.size,
                self.BLOCKS_COL:
                    lambda f: "%d" % len(f.block_addrs_set),
            }

            return mapping[col](func)

        elif role == Qt.ForegroundRole:
            # calculate the foreground color

            color = QColor(0, 0, 0)
            if func.is_syscall:
                color = QColor(0, 0, 0x80)
            elif func.is_plt:
                color = QColor(0, 0x80, 0)
            elif func.is_simprocedure:
                color = QColor(0x80, 0, 0)

            #for w in widgets:
            #    w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            #    w.setForeground(color)

            return QBrush(color)

    def sort(self, column, order):
        mapping = {
            self.NAME_COL:
                lambda: sorted(self.func_list, key=lambda f: f.name, reverse=order==Qt.DescendingOrder),
            self.ADDRESS_COL:
                lambda: sorted(self.func_list, key=lambda f: f.addr, reverse=order==Qt.DescendingOrder),
            self.BINARY_COL:
                lambda: sorted(self.func_list, key=lambda f: self._get_binary_name(f), reverse=order==Qt.DescendingOrder),
            self.SIZE_COL:
                lambda: sorted(self.func_list, key=lambda f: f.size, reverse=order==Qt.DescendingOrder),
            self.BLOCKS_COL:
                lambda: sorted(self.func_list, key=lambda f: len(f.block_addrs_set), reverse=order==Qt.DescendingOrder),
        }

        self.func_list = mapping[column]()

    #
    # Private methods
    #

    def _get_binary_name(self, func):
        return os.path.basename(func.binary.binary) if func.binary is not None else ""


class QFunctionTable(QTableView):
    def __init__(self, parent, selection_callback=None):
        super(QFunctionTable, self).__init__(parent)

        self._selected = selection_callback

        self.horizontalHeader().setVisible(True)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)

        # sorting
        # self.horizontalHeader().setSortIndicatorShown(True)

        self.verticalHeader().setResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self._functions = None
        self._model = QFunctionTableModel()
        self.setModel(self._model)

        # slots
        self.horizontalHeader().sortIndicatorChanged.connect(self.sortByColumn)
        self.doubleClicked.connect(self._on_function_selected)

    @property
    def function_manager(self):
        return self._functions

    @function_manager.setter
    def function_manager(self, functions):
        self._functions = functions
        self._model.func_list = list(self._functions.values())

        self.resizeColumnsToContents()

    def _on_function_selected(self, model_index):
        row = model_index.row()
        if 0 <= row < len(self._model):
            selected_func = self._model.func_list[row]
        else:
            selected_func = None

        if self._selected is not None:
            self._selected(selected_func)
