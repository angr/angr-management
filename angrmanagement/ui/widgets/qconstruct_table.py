

from PySide.QtGui import QTableWidget, QTableWidgetItem, QColor, QAbstractItemView
from PySide.QtCore import Qt

from angr.misc import repr_addr


class ConstructTypes(object):
    Loop = "Loop"


class QConstructTableItem(QTableWidgetItem):
    def __init__(self, addr, func_addr, construct_type, *args, **kwargs):
        super(QConstructTableItem, self).__init__(*args, **kwargs)

        self.addr = addr
        self.func_addr = func_addr
        self.construct_type = construct_type

    def widgets(self):
        """

        :return: a list of QTableWidgetItem objects
        :rtype: list
        """

        raise NotImplementedError()


class QConstructTableLoopItem(QConstructTableItem):
    def __init__(self, loop_analysis, func_addr, *args, **kwargs):

        self.loop = loop_analysis.loop
        self.loop_analysis = loop_analysis

        super(QConstructTableLoopItem, self).__init__(self.loop.entry.addr, func_addr, ConstructTypes.Loop, *args, **kwargs)

        self.loop_bounded = "" if self.loop_analysis.bounded is None else str(self.loop_analysis.bounded)

    def widgets(self):

        address = repr_addr(self.addr)
        func_addr = repr_addr(self.func_addr)

        widgets = [
            QTableWidgetItem(func_addr),
            QTableWidgetItem(address),
            QTableWidgetItem(self.construct_type),
            QTableWidgetItem(self.loop_bounded),
        ]

        for w in widgets:
            w.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

        return widgets


class QConstructTable(QTableWidget):
    def __init__(self, parent):
        super(QConstructTable, self).__init__(parent)

        header_labels = [ 'Function', 'Address', 'Type', 'Loop Bounded?' ]

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setHorizontalScrollMode(self.ScrollPerPixel)

        self._loops = None
        self._function = None

        self.items = [ ]

        self.cellDoubleClicked.connect(self._on_construct_selected)

    #
    # Properties
    #

    @property
    def loops(self):
        return self.loops

    @loops.setter
    def loops(self, v):
        self._loops = v
        self.reload()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v):
        self._function = v
        self.reload()

    #
    # Public methods
    #

    def reload(self):

        current_row = self.currentRow()

        self.clearContents()

        self.items = [ ]

        if not self._loops:
            return

        for loop_analysis, func_addr in self._loops:
            if self._function is None:
                self.items.append(QConstructTableLoopItem(loop_analysis, func_addr))
            else:
                if self._function == func_addr:
                    self.items.append(QConstructTableLoopItem(loop_analysis, func_addr))

        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        if 0 <= current_row < len(self.items):
            self.setCurrentCell(current_row, 0)

        self.setVisible(False)
        self.resizeColumnsToContents()
        self.setVisible(True)

    #
    # Event handlers
    #

    def _on_construct_selected(self, *args):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            selected_item = self.items[selected_index]
        else:
            selected_item = None

        if self._selected is not None:
            self._selected(selected_item)
