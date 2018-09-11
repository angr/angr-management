from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PySide2.QtCore import Qt


class AddressTableWidgetItem(QTableWidgetItem):
    def __init__(self, address):
        super(AddressTableWidgetItem, self).__init__("%x" % address)

        self.address = address

    def __le__(self, other):
        return self.address <= other.address


class QXRefViewerItem(object):
    def __init__(self, variable_access):
        self._variable_access = variable_access

    def widgets(self):

        access_type_str = self._variable_access.access_type
        ident_str = self._variable_access.variable.ident

        widgets = [
            QTableWidgetItem(access_type_str),
            QTableWidgetItem(ident_str),
            QTableWidgetItem(AddressTableWidgetItem(self._variable_access.location.ins_addr)),
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

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

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
