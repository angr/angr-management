from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PySide2.QtCore import Qt


class QUserItem:
    def __init__(self, struct_name, size, user):
        self.sturct_name = struct_name
        self.size = size
        self.user = user

    def widgets(self):
        u = self.user

        widgets = [
            QTableWidgetItem(self.sturct_name),
            QTableWidgetItem(str(self.size)),
            QTableWidgetItem(u),  # normally u.name
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

    def _build_table(self):
        pass


class QStructInfoTable(QTableWidget):
    HEADER = [
        'Struct Name',
        'Size',
        'User',
    ]

    def __init__(self, controller, parent=None):
        super().__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # so text does not get cut off
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self.items = []

        self.controller = controller

    def reload(self):
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

        self.viewport().update()

    def selected_user(self):
        try:
            idx = next(iter(self.selectedIndexes()))
        except StopIteration:
            # Nothing is selected
            return None
        item_idx = idx.row()
        if 0 <= item_idx < len(self.items):
            user_name = self.items[item_idx].user.name
        else:
            user_name = None
        return user_name

    def select_user(self, user_name):
        for i, item in enumerate(self.items):
            if item.user.name == user_name:
                self.selectRow(i)
                break

    def update_users(self, users):
        """
        Update the status of all users within the repo.
        """

        # reset the QItem list
        self.items = []

        # First, let's see if any new homies showed up
        #self.controller._client.init_remote()

        for user in users:
            self.items.append(QUserItem("", 0, user.name))

        self.reload()
