
from PySide.QtGui import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PySide.QtCore import Qt


class QXRefViewerItem(object):
    def __init__(self, variable_access):
        self._variable_access = variable_access

    def widgets(self):

        access_type_str = self._variable_access.access_type
        ident_str = self._variable_access.variable.ident
        address_str = "%x" % self._variable_access.location.ins_addr

        widgets = [
            QTableWidgetItem(access_type_str),
            QTableWidgetItem(ident_str),
            QTableWidgetItem(address_str),
            QTableWidgetItem("TODO"),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QXRefViewer(QTableWidget):
    def __init__(self, variable_manager, variable, parent=None):
        super(QXRefViewer, self).__init__(parent)

        header = [ 'Type', 'Var. Ident.', 'Address', 'Text' ]

        self.setColumnCount(len(header))
        self.setHorizontalHeaderLabels(header)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setShowGrid(False)

        self.verticalHeader().setResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self._variable_manager = variable_manager
        self._variable = variable

        self.items = [ ]

        self._reload()

    def _reload(self):
        accesses = self._variable_manager.get_variable_accesses(self._variable, same_name=True)

        self.items = [ QXRefViewerItem(acc) for acc in accesses ]

        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)
