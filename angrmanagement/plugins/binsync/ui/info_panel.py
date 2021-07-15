from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QComboBox

from angrmanagement.ui.views.view import BaseView
from .info_tables import QFuncInfoTable
from .info_tables.struct_info_table import QStructInfoTable

from ..controller import BinsyncController, SyncControlStatus


class InfoView(BaseView):
    """
    The class for the window that shows changes/info to BinSync data. This includes things like
    changes to functions or structs.
    """

    def __init__(self, workspace, default_docking_position, controller, *args, **kwargs):
        super().__init__('sync', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = "BinSync: Info View"

        self._status_label = None  # type: QLabel
        self._team_table = None  # type: QTeamTable

        # info tables
        self._func_table = None  # type: QFuncInfoTable
        self._struct_table = None  # type: QStructInfoTable
        self._active_table = None  # type: QTableWidget
        self.controller: BinsyncController = controller

        self._init_widgets()

        self.width_hint = 250

        # subscribe
        # self.workspace.instance.sync.users_container.am_subscribe(self._update_info_tables)

    def reload(self):
        # reload the status
        status = self.controller.status
        if status == SyncControlStatus.CONNECTED:
            self._status_label.setStyleSheet("color: green")
        elif SyncControlStatus.CONNECTED_NO_REMOTE:
            self._status_label.setStyleSheet("color: yellow")
        else:
            self._status_label.setStyleSheet("color: red")
        self._status_label.setText(self.controller.status_string)

        # reload the info tables
        if self.controller.check_client():
            self._update_info_tables()

    #
    # Private methods
    #

    def _init_widgets(self):
        # status box
        status_box = QGroupBox(self)
        status_box.setTitle("Status")
        self._status_label = QLabel(self)
        self._status_label.setText("Not Connected")
        status_layout = QVBoxLayout()
        status_layout.addWidget(self._status_label)
        status_box.setLayout(status_layout)

        # info box
        info_box = QGroupBox(self)
        info_box.setTitle("Info Table")
        info_layout = QVBoxLayout()

        # table selector
        combo_box = QGroupBox(self)
        combo_layout = QHBoxLayout()
        self.combo = QComboBox()
        self.combo.addItems(["Functions", "Structs"])
        self.combo.currentTextChanged.connect(self._on_combo_change)
        combo_layout.addWidget(self.combo)
        combo_box.setLayout(combo_layout)
        info_layout.addWidget(combo_box)

        # function info table
        self._func_table = QFuncInfoTable(self.controller)
        info_layout.addWidget(self._func_table)  # stretch=1 optional
        self._active_table = self._func_table

        # struct info table
        self._struct_table = QStructInfoTable(self.controller)
        self._struct_table.hide()
        info_layout.addWidget(self._struct_table)

        info_box.setLayout(info_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(info_box)

        self.setLayout(main_layout)
        # self.setFixedWidth(500)

    def _on_combo_change(self, value):
        self._hide_all_tables()
        if value == "Functions":
            self._func_table.show()
            self._active_table = self._func_table
        elif value == "Structs":
            self._struct_table.show()
            self._active_table = self._struct_table

    def _hide_all_tables(self):
        self._func_table.hide()
        self._struct_table.hide()

    def _update_info_tables(self):
        if self.controller.sync.has_remote:
            self.controller.sync.client.init_remote()


        self._active_table.update_users(self.controller.sync.users())
