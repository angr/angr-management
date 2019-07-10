
from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView
from PySide2.QtCore import Qt


class QPatchTableItem:
    def __init__(self, patch):
        self.patch = patch

    def widgets(self):
        patch = self.patch

        widgets = [
            QTableWidgetItem(patch.addr),
            QTableWidgetItem(len(patch)),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QPatchTable(QTableWidget):

    HEADER = ['Address', 'Bytes']

    def __init__(self, instance, parent):
        super(QPatchTable, self).__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.items = [ ]
        self.instance = instance
        self.instance.patches.am_subscribe(self._watch_patches)

    def current_patch(self):
        selected_index = self.currentRow()
        if 0 <= selected_index < len(self.items):
            return self.items[selected_index]
        else:
            return None

    def reload(self):
        current_row = self.currentRow()
        self.clearContents()

        self.items = [QPatchTableItem(item) for item in self.instance.patches.items()]
        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        #if 0 <= current_row < len(self.items):
        #    self.setCurrentItem(current_row, 0)

    def _on_state_selected(self, *args):
        if self._selected is not None:
            self._selected(self.current_state_record())

    def _watch_patches(self, **kwargs):
        self.reload()
