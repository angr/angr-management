from PySide2.QtWidgets import QDialog, QLabel, QComboBox, QTableWidget, QTableWidgetItem, \
    QDialogButtonBox, QGridLayout, QHeaderView, QAbstractItemView

from .sync_ctrl import Controller
#
#   MenuDialog Box for Binsync Actions
#


class MenuDialog(QDialog):
    def __init__(self, menu_table, parent=None):
        super().__init__(parent)

        self.menu_table = menu_table

        label = QLabel("Binsync Action")
        self.combo = QComboBox()
        self.combo.addItems(["Sync", "Sync All", "Sync Structs"])

        self.tableWidget = QTableWidget(len(self.menu_table), 4)
        self.tableWidget.setHorizontalHeaderLabels(
            "User;Last Push;Last Edited Function;Local Name".split(";")
        )

        header = self.tableWidget.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        for item, row in zip(self.menu_table.items(), range(len(self.menu_table))):
            user_item = QTableWidgetItem(item[0])
            push_item = QTableWidgetItem(item[1][0])
            func_item = QTableWidgetItem(item[1][1])
            func_name_item = QTableWidgetItem(item[1][2])
            self.tableWidget.setItem(row, 0, user_item)
            self.tableWidget.setItem(row, 1, push_item)
            self.tableWidget.setItem(row, 2, func_item)
            self.tableWidget.setItem(row, 3, func_name_item)

        # set more table properties
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection)

        box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            centerButtons=True,
        )
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)

        lay = QGridLayout(self)
        lay.addWidget(label, 0, 0)
        lay.addWidget(self.combo, 0, 1)
        lay.addWidget(self.tableWidget, 1, 0, 1, 2)
        lay.addWidget(box, 2, 0, 1, 2)

        self.resize(640, 240)

    def getActionSelection(self):
        # defaults to "Sync"
        action = self.combo.currentText()

        selected_rows = self.tableWidget.selectionModel().selectedRows()
        if len(selected_rows) == 0:
            return action, None

        selected_row = selected_rows[0].row()
        selected_user = list(self.menu_table)[selected_row]
        return action, selected_user

#
#   Actions
#


class SyncMenu:
    def __init__(self, controller, funcs):
        self.controller: Controller = controller
        self.selected_funcs = funcs

    def open_sync_menu(self):
        """
        Opens sync menu and gives the optinal actions
        """
        # create a dynamic menu table for the users
        menu_table = self._build_menu_table()

        # open a dialog to make sync actions
        dialog = MenuDialog(menu_table)
        result = dialog.exec_()

        # only parse the action if the user accepted the result
        if result != QDialog.Accepted:
            return

        # parse action
        action, user = dialog.getActionSelection()

        for func in self.selected_funcs:
            ret = self._do_action(action, user, func)
            if not ret:
                return

    # pylint:disable=no-self-use
    def _do_action(self, action, user, func):
        if user is None:
            print("[Binsync]: Error! No user selected for syncing.")
            return False

        if action == "Sync":
            print(f"[Binsync]: Data has been synced from user: {user} on {hex(func)}.")

        elif action == "Toggle autosync":
            # TODO: implement auto-syncing
            print("[Binsync]: Auto Sync not implemented yet.")

        elif action == "Sync All":
            print(f"[Binsync]: All data has been synced from user: {user}.")

        elif action == "Sync Structs":
            print(f"[Binsync]: All structs have been synced from user: {user}")

        else:
            print("[Binsync]: Error parsing sync action!")
            return False

        return True

    def _build_menu_table(self):
        """
        Builds a menu for use in the Dialog

        In the form of {user: (last_change, last_push_func)}
        :return:
        """
        # First, let's see if any new users has joined repo
        #self.controller.client.init_remote()

        # Build out the menu dictionary for the table
        menu_table = {}
        for user in self.controller.users:
            last_time = int(user.last_push_time)
            last_func = int(user.last_push_func)

            if last_time == -1 or last_func == -1 or last_func == 0:
                ret_string = (" ", " ", " ")
            else:
                time_ago = 0  # BinsyncController.friendly_datetime(last_time)
                local_name = "local_temp"  # compat.get_func_name(last_func)
                func = hex(last_func)
                ret_string = (time_ago, func, local_name)

            # Set table attributes | [PUSH TIME] | [FUNC ADDR] | [LOCAL NAME]
            menu_table[user.name] = ret_string

        return menu_table
