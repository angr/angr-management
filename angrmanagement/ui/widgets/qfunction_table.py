
from PySide.QtGui import QTableWidget, QTableWidgetItem, QColor, QAbstractItemView
from PySide.QtCore import Qt, QSize


class QFunctionTableItem(QTableWidgetItem):
    def __init__(self, function, *args, **kwargs):
        super(QFunctionTableItem, self).__init__(*args, **kwargs)

        self._function = function

    def widgets(self):
        """

        :param angr.knowledge.Function function: The Function object.
        :return: a list of QTableWidgetItem objects
        :rtype: list
        """

        function = self._function

        name = function.name
        address = function.addr
        blocks = len(list(function.blocks))
        size = "Unknown"

        widgets = [
            QTableWidgetItem(name),
            QTableWidgetItem("%x" % address),
            QTableWidgetItem(size),
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

        self.setColumnCount(4)
        self.setHorizontalHeaderLabels([ 'Name', 'Address', 'Size', 'Blocks' ])
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

        self._functions = None
        self.items = [ ]

        self.itemSelectionChanged.connect(self._on_function_selected)

    def set_functions(self, functions):
        self._functions = functions
        self.reload()

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

    def _on_function_selected(self):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            selected_item = self.items[selected_index]
        else:
            selected_item = None
            selected_index = -1

        if self._selected is not None:
            self._selected(selected_item._function)
