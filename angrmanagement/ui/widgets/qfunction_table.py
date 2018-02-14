
import os

from PySide.QtGui import QTableWidget, QTableWidgetItem, QColor, QAbstractItemView, QHeaderView
from PySide.QtCore import Qt, QSize


class QFunctionTableAddressItem(QTableWidgetItem):
    def __init__(self, address):
        super(QFunctionTableAddressItem, self).__init__("%x" % address)
        self.address = address

    def __lt__(self, other):
        return self.address < other.address


class QFunctionTableItem(object):
    def __init__(self, function):
        self._function = function

    def widgets(self):
        """

        :param angr.knowledge_plugins.Function function: The Function object.
        :return: a list of QTableWidgetItem objects
        :rtype: list
        """

        function = self._function

        name = function.name
        address = function.addr
        binary = function.binary
        if binary is not None:
            binary_name = os.path.basename(binary.binary)
        else:
            binary_name = ""
        blocks = len(list(function.blocks))
        size = function.size

        widgets = [
            QTableWidgetItem(name),
            QFunctionTableAddressItem(address),
            QTableWidgetItem(binary_name),
            QTableWidgetItem("%d" % size),
            QTableWidgetItem("%d" % blocks),
        ]

        color = QColor(0, 0, 0)
        if function.is_syscall:
            color = QColor(0, 0, 0x80)
        elif function.is_plt:
            color = QColor(0, 0x80, 0)
        elif function.is_simprocedure:
            color = QColor(0x80, 0, 0)

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)
            w.setForeground(color)

        return widgets


class QFunctionTable(QTableWidget):
    def __init__(self, parent, selection_callback=None):
        super(QFunctionTable, self).__init__(parent)

        self._selected = selection_callback

        header = [ 'Name', 'Address', 'Binary', 'Size', 'Blocks' ]

        self.setColumnCount(len(header))
        self.setHorizontalHeaderLabels(header)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)

        # sorting
        self.horizontalHeader().setSortIndicatorShown(True)
        self._last_sorting_column = None
        self._last_sorting_order = None

        self.verticalHeader().setResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self._functions = None
        self.items = [ ]

        # slots
        self.cellDoubleClicked.connect(self._on_function_selected)
        self.horizontalHeader().sectionClicked.connect(self._on_horizontal_header_clicked)

    @property
    def function_manager(self):
        return self._functions

    @function_manager.setter
    def function_manager(self, functions):
        self._functions = functions
        self.reload()
        self.hide()
        self.resizeColumnsToContents()
        self.show()

    def reload(self):

        current_row = self.currentRow()

        self.clearContents()

        if self._functions is None:
            return

        self.items = [QFunctionTableItem(f) for f in self._functions.values()]

        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        if 0 <= current_row < len(self.items):
            self.setCurrentIndex(current_row)

    def _on_function_selected(self, *args):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            selected_item = self.items[selected_index]
        else:
            selected_item = None
            selected_index = -1

        if self._selected is not None:
            self._selected(selected_item._function)

    def _on_horizontal_header_clicked(self, column_number):
        if column_number != self._last_sorting_column:
            self._last_sorting_column = column_number
            self._last_sorting_order = 0

            self.setSortingEnabled(True)
            self.sortByColumn(column_number, Qt.SortOrder(0))

        else:
            if self._last_sorting_order == 0:
                self._last_sorting_order = 1
            elif self._last_sorting_order == 1:
                self._last_sorting_order = None
            elif self._last_sorting_order is None:
                self._last_sorting_order = 0

            if self._last_sorting_order is None:
                # roll back to the default sorting mechanism: Sorting by address
                self.sortByColumn(1, Qt.SortOrder(0))
                # disable sorting
                self.setSortingEnabled(False)
            else:
                self.setSortingEnabled(True)
                self.sortByColumn(column_number, Qt.SortOrder(self._last_sorting_order))
