from enaml.widgets.api import RawWidget
from enaml.core.declarative import d_
from atom.api import List, Bool, set_default, observe, Typed
from enaml.qt.QtGui import QTableWidget, QTableWidgetItem, QFont
from enaml.qt.QtCore import Qt

class Table(RawWidget):
    data_list = d_(List())
    data_matrix = d_(List())
    column_names = d_(List())
    row_names = d_(List())
    horizontal_scroll = d_(Bool(True))
    vertical_scroll = d_(Bool(True))

    _item_font = Typed(QFont)
    _table = Typed(QTableWidget)

    hug_width = set_default('ignore')
    hug_height = set_default('ignore')

    def create_widget(self, parent):
        self._table = table = QTableWidget(parent)
        table.setColumnCount(len(self.column_names))
        table.setRowCount(len(self.row_names))
        table.horizontalHeader().setMinimumSectionSize(1)
        table.verticalHeader().setMinimumSectionSize(1)
        #table.horizontalHeader().setResizeMode(QHeaderView.ResizeToContents)
        #table.verticalHeader().setResizeMode(QHeaderView.ResizeToContents)

        header_font = QFont("Monospace")
        header_font.setBold(True)
        table.horizontalHeader().setFont(header_font)
        table.verticalHeader().setFont(header_font)

        if not self.horizontal_scroll:
            table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        if not self.vertical_scroll:
            table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self._item_font = QFont("Monospace")
        self.update_data()

        table.setHorizontalHeaderLabels(self.column_names)
        table.setVerticalHeaderLabels(self.row_names)

        table.resizeColumnsToContents()
        table.resizeRowsToContents()

        return table

    @observe('data_list', 'data_matrix')
    def update_data(self, _change=None):
        for col in range(len(self.column_names)):
            for row in range(len(self.row_names)):
                try:
                    if len(self.data_list) > 0:
                        item = QTableWidgetItem(str(self.data_list[row*len(self.column_names)+col]))
                    elif len(self.data_matrix) > 0:
                        item = QTableWidgetItem(str(self.data_matrix[row][col]))
                except (IndexError, KeyError):
                    continue

                item.setFont(self._item_font)
                self._table.setItem(row, col, item)
