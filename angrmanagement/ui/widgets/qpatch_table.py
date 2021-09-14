
import binascii

from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView
from PySide2.QtCore import Qt


class QPatchTableItem:
    """
    Item in the patch table describing a patch.
    """

    def __init__(self, patch, old_bytes):
        self.patch = patch
        self.old_bytes = old_bytes

    def widgets(self):
        patch = self.patch

        widgets = [
            QTableWidgetItem("%#x" % patch.addr),
            QTableWidgetItem("%d bytes" % len(patch)),
            QTableWidgetItem(binascii.hexlify(self.old_bytes).decode("ascii") if self.old_bytes else "<unknown>"),
            QTableWidgetItem(binascii.hexlify(patch.new_bytes).decode("ascii")),
            QTableWidgetItem(patch.comment or ''),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QPatchTable(QTableWidget):
    """
    Table of all patches.
    """

    HEADER = ['Address', 'Size', 'Old Bytes', 'New Bytes', 'Comment']

    def __init__(self, instance, parent):
        super().__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.verticalHeader().setVisible(False)

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
        self.clearContents()

        self.items = [QPatchTableItem(item,
                                      self._get_bytes(self.instance.project, item.addr, len(item)))
                      for item in self.instance.project.kb.patches.values()]
        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

    def _on_state_selected(self, *args):  # pylint: disable=unused-argument
        if self._selected is not None:
            self._selected(self.current_state_record())

    def _watch_patches(self, **kwargs):  # pylint: disable=unused-argument
        if not self.instance.patches.am_none:
            self.reload()

    @staticmethod
    def _get_bytes(proj, addr, size):
        try:
            return proj.loader.memory.load(addr, size)
        except KeyError:
            return None
