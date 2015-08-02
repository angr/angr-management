from enaml.widgets.api import RawWidget
from enaml.core.declarative import d_
from atom.api import List, Bool #, set_default
from enaml.qt.QtGui import QTableWidget, QTableWidgetItem, QFont
from enaml.qt.QtCore import Qt

class Table(RawWidget):
    data_list = d_(List())
    data_matrix = d_(List())
    column_names = d_(List())
    row_names = d_(List())
    horizontal_scroll = d_(Bool(False))
    vertical_scroll = d_(Bool(False))

    #hug_width = set_default('ignore')
    #hug_height = set_default('ignore')

    def create_widget(self, parent):
        table = QTableWidget(parent)
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

        item_font = QFont("Monospace")
        for col in range(len(self.column_names)):
            for row in range(len(self.row_names)):
                try:
                    if len(self.data_list) > 0:
                        item = QTableWidgetItem(str(self.data_list[row*len(self.column_names)+col]))
                    elif len(self.data_matrix) > 0:
                        item = QTableWidgetItem(str(self.data_matrix[row][col]))
                except (IndexError, KeyError):
                    continue

                item.setFont(item_font)
                table.setItem(row, col, item)

        table.setHorizontalHeaderLabels(self.column_names)
        table.setVerticalHeaderLabels(self.row_names)
        self.shrink_to_fit(table)
        return table

    @staticmethod
    def shrink_to_fit(table):
        table.resizeColumnsToContents()
        table.resizeRowsToContents()

        #print [ table.columnWidth(c) for c in range(table.columnCount()) ]
        #print [ table.rowHeight(r) for r in range(table.rowCount()) ]

        table_width = 3+table.horizontalHeader().width() + sum(table.columnWidth(c) for c in range(table.columnCount()))
        table_height = table.verticalHeader().width() + sum(table.rowHeight(r) for r in range(table.rowCount()))
        table.setMaximumHeight(table_height)
        table.setMinimumHeight(table_height)
        table.setMaximumWidth(table_width)
        table.setMinimumWidth(table_width)
