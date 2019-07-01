
from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QMenu, QHeaderView
from PySide2.QtCore import Qt


class QUserItem:
    def __init__(self, user):
        super().__init__()

        self.user = user

    def widgets(self):

        u = self.user

        widgets = [
            QTableWidgetItem(u.name),
        ]

        return widgets


class QTeamTable(QTableWidget):

    HEADER = [
        'User',
        'Last update',
        'Auto pull',
    ]

    def __init__(self, instance, parent=None):
        super().__init__(parent)

        self.setColumnCount(len(self.HEADER))
        self.setHorizontalHeaderLabels(self.HEADER)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)

        self.verticalHeader().setVisible(False)
        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)

        self.items = [ ]

    def reload(self):
        self.clearContents()
        self.setRowCount(len(self.items))

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)

    def update_users(self, users):

        self.items.clear()

        for u in users:
            self.items.append(QUserItem(u))

        self.reload()
