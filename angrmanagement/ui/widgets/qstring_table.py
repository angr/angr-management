from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView
from PySide2.QtGui import QColor
from PySide2.QtCore import Qt

from angr.analyses.cfg.cfg_fast import MemoryData

from ...utils import filter_string_for_display


class QStringTableItem(QTableWidgetItem):
    def __init__(self, mem_data, *args, **kwargs):
        super(QStringTableItem, self).__init__(*args, **kwargs)

        self._mem_data = mem_data  # type: MemoryData

    def widgets(self):
        """

        :return: a list of QTableWidgetItem objects
        :rtype: list
        """

        str_data = self._mem_data

        address = "%#x" % str_data.address
        length = "%d" % str_data.size
        content = filter_string_for_display(str_data.content.decode("utf-8"))


        widgets = [
            QTableWidgetItem(address),
            QTableWidgetItem(length),
            QTableWidgetItem(content),
        ]

        for w in widgets:
            w.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)

        return widgets


class QStringTable(QTableWidget):
    def __init__(self, parent, selection_callback=None):
        super(QStringTable, self).__init__(parent)

        self._selected = selection_callback

        header_labels = [ 'Address', 'Length', 'String' ]

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setHorizontalScrollMode(self.ScrollPerPixel)

        self._cfg = None
        self._function = None
        self.items = [ ]

        # self.itemDoubleClicked.connect(self._on_string_selected)
        self.cellDoubleClicked.connect(self._on_string_selected)

    #
    # Properties
    #

    @property
    def cfg(self):
        return self._cfg

    @cfg.setter
    def cfg(self, v):
        self._cfg = v
        self.reload()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, v):
        if v is not self._function:
            self._function = v
            self.reload()

    #
    # Public methods
    #

    def reload(self):

        current_row = self.currentRow()

        self.clearContents()

        if self._cfg is None:
            return

        self.items = [ ]

        for f in self._cfg.memory_data.values():
            if f.sort == 'string':
                if self._function is None:
                    self.items.append(QStringTableItem(f))
                else:
                    for irsb_addr, _, _ in f.refs:
                        if irsb_addr in self._function.block_addrs_set:
                            self.items.append(QStringTableItem(f))
                            break

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

    def _on_string_selected(self, *args):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            selected_item = self.items[selected_index]
        else:
            selected_item = None

        if self._selected is not None:
            self._selected(selected_item)

