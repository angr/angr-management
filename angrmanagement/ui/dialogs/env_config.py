from PySide2.QtCore import Qt
from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, \
    QMenu, QHeaderView, QDialog, QVBoxLayout

class EnvTable(QTableWidget):
    '''
    Environment Config Table
    '''
    def __init__(self, items, parent):
        super().__init__(parent)

        header_labels = ['Name', 'Value']

        self.setColumnCount(len(header_labels))
        self.setHorizontalHeaderLabels(header_labels)
        self.setSelectionBehavior(QAbstractItemView.SelectItems)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        self.setRowCount(len(items))
        for idx, item in enumerate(items):
            for i, it in enumerate(item):
                self.setItem(idx, i, QTableWidgetItem(it))

    def contextMenuEvent(self, event):
        menu = QMenu("", self)

        menu.addAction('Add a Row', self._action_new_row)
        menu.addAction('Delete this Row', self._action_delete)

        menu.exec_(event.globalPos())

    def _action_new_row(self):
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, QTableWidgetItem("change me"))
        self.setItem(row, 1, QTableWidgetItem(""))

    def _action_delete(self):
        self.removeRow(self.currentRow())

    def get_result(self):
        ret = []
        for i in range(self.rowCount()):
            ret.append([self.item(i,0).text(), self.item(i,1).text()])
        return ret


class EnvConfig(QDialog):
    '''
    Environment Config Dialog for new state
    '''
    def __init__(self, env_config=None, instance=None, parent=None):
        super().__init__(parent)

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self._instance = instance
        self._parent = parent
        self.env_config = env_config or []
        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()
        self._table = EnvTable(self.env_config,self)
        layout.addWidget(self._table,0)
        self.setLayout(layout)

    def closeEvent(self, event): #pylint: disable=unused-argument
        self.env_config = self._table.get_result()
        self.close()
