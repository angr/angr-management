from typing import Dict

from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PySide2.QtCore import Qt

from ...controller import BinsyncController

try:
    import binsync
except ImportError:
    binsync = None
if binsync:
    from binsync.data import Function  # pylint:disable=import-error


class QUserItem:
    """
    A user item found inside a QFunctionTable. Should only ever be used inside
    the QFunctionTable class.
    """
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
    """
    A QTable that contains update information about functions in the BinSync Project.
    The table will show:

    [Func Addr, Local Name, User Name, Last Push Time]

    The QUserItem class is used to fill each row of the table.
    """
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

        self.controller: BinsyncController = controller

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

        # reset the items in table
        self.items = []
        known_funcs = {}  # addr: (addr, name, user_name, push_time)

        # first check if any functions are unknown to the table
        for user in users:
            state = self.controller.sync.client.get_state(user=user.name)
            user_funcs: Dict[int, Function] = state.functions

            for func_addr, sync_func in user_funcs.items():
                func_change_time = sync_func.last_change

                # check if we already know about it
                if func_addr in known_funcs:
                    # compare this users change time to the store change time
                    if func_change_time < known_funcs[func_addr][3]:
                        # don't change it if the other user is more recent
                        continue

                local_func_name = self.controller.get_local_func_name(func_addr)
                known_funcs[func_addr] = [func_addr, local_func_name, user.name, func_change_time]

        for row in known_funcs.values():
            # fix datetimes for the correct format
            row[3] = BinsyncController.friendly_datetime(row[3])
            table_row = QUserItem(*row)
            self.items.append(table_row)

        self.reload()
