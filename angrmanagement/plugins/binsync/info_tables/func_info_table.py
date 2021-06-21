from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PySide2.QtCore import Qt
from typing import Dict

from binsync.data import Function


class QUserItem:
    def __init__(self, func_addr, local_name, user, last_push):
        self.func_addr = func_addr
        self.local_name = local_name
        self.user = user
        self.last_push = last_push

    def widgets(self):
        u = self.user

        widgets = [
            QTableWidgetItem(hex(self.func_addr)),
            QTableWidgetItem(self.local_name),
            QTableWidgetItem(u),  # normally u.name
            QTableWidgetItem(self.last_push),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets

    def _build_table(self):
        pass


class QFuncInfoTable(QTableWidget):
    HEADER = [
        'Changed Func',
        'Local Name',
        'User',
        'Last Push',
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

        # Dict to track function changes
        func_changes = {}

        for user in users:
            # Get user state. Func from user state
            #s = self.controller._client.get_state(user=user.name)
            functions: Dict[int, Function] = {} # s.functions

            # Per user metadata
            u_name = user.name

            # Iterate over items, store last updated
            for addr, func in functions.items():
                # Function metadata
                last_change = func.last_change
                local_name = "local_func"
                time_delta = -1

                # Check last changes and set table
                try:
                    # Check if this is newer or not
                    stored_time = func_changes[addr][3]
                    if last_change > stored_time:
                        func_changes[addr] = (local_name, u_name, time_delta, last_change)
                except KeyError:
                    # IN this case, it probably does not exist
                    # Let's make it
                    func_changes[addr] = (local_name, u_name, time_delta, last_change)

        # Create the table
        for key in sorted(func_changes):
            # Assign attribute by val: <func_addr> | <local_name> | <u_name> | <time_delta>
            item = func_changes[key]
            self.items.append(QUserItem(key, item[0], item[1], item[2]))
        self.reload()
