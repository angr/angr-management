
from PySide2.QtWidgets import QVBoxLayout, QGroupBox, QLabel

from .view import BaseView
from ..widgets.qteam_table import QTeamTable


class SyncView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('sync', workspace, default_docking_position, *args, **kwargs)

        self.caption = "Sync"

        self._status_label = None  # type: QLabel
        self._team_table = None  # tpe: QTeamTable

        self._init_widgets()

        # subscribe
        self.workspace.instance.sync.users_container.am_subscribe(self._update_users)

    def reload(self):
        self._status_label.setText(self.workspace.instance.sync.status_string)

    #
    # Private methods
    #

    def _init_widgets(self):

        # status
        status_box = QGroupBox(self)
        status_box.setTitle("Status")

        self._status_label = QLabel(self)
        self._status_label.setText(self.workspace.instance.sync.status_string)

        status_layout = QVBoxLayout()
        status_layout.addWidget(self._status_label)

        status_box.setLayout(status_layout)

        # table

        self._team_table = QTeamTable(self.workspace.instance)
        team_box = QGroupBox(self)
        team_box.setTitle("Team")

        team_layout = QVBoxLayout()
        team_layout.addWidget(self._team_table)
        team_box.setLayout(team_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(status_box)
        main_layout.addWidget(team_box)

        self.setLayout(main_layout)

    #
    # Event callbacks
    #

    def _update_users(self):
        self._team_table.update_users(self.workspace.instance.sync.users)
