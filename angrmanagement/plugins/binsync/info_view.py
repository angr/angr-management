from PySide2.QtWidgets import QVBoxLayout, QHBoxLayout, QGroupBox, QLabel, QMessageBox, QComboBox

from ...ui.views.view import BaseView
from ...data.sync_ctrl import SyncControlStatus, STATUS_TEXT
from .info_tables.func_info_table import QFuncInfoTable
from .info_tables.struct_info_table import QStructInfoTable


class InfoView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('sync', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = "BinSync: Info View"

        self._status_label = None  # type: QLabel
        self._team_table = None  # type: QTeamTable

        # info tables
        self._func_table = None  # type: QFuncInfoTable
        self._struct_table = None  # type: QStructInfoTable
        self._active_table = None  # type: QTableWidget
        self._controller = workspace.instance.sync

        self._init_widgets()

        self.width_hint = 250

        # subscribe
        self.workspace.instance.sync.users_container.am_subscribe(self._update_users)

    def reload(self):
        status = self.workspace.instance.sync.status_string
        if status == STATUS_TEXT[SyncControlStatus.CONNECTED]:
            self._status_label.setStyleSheet("color: green")
        else:
            self._status_label.setStyleSheet("color: red")
        self._status_label.setText(status)

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
        self._func_table = QFuncInfoTable(self._controller)
        info_layout.addWidget(self._func_table)  # stretch=1 optional
        self._active_table = self._func_table

        # struct info table
        self._struct_table = QStructInfoTable(self._controller)
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

    def _update_users(self):
        self._active_table.update_users(self.workspace.instance.sync.users)

    #
    # Event callbacks
    #

    def _on_pullfunc_clicked(self):
        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        if disasm_view is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine the current function. No disassembly view is open.")
            return

        current_function = disasm_view._current_function
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "No function is current in the disassembly view.")
            return

        # which user?
        u = self._team_table.selected_user()
        if u is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine which user to pull from. "
                                 "Please select a user in the team table first.")
            return

        self.workspace.instance.project.kb.sync.fill_function(current_function, user=u)

        # trigger a refresh
        disasm_view.refresh()

    def _on_pushfunc_clicked(self):

        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        if disasm_view is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine the current function. No disassembly view is open.")
            return

        current_function = disasm_view._current_function
        if current_function is None:
            QMessageBox.critical(None, 'Error',
                                 "No function is current in the disassembly view.")
            return

        func = current_function
        kb = self.workspace.instance.project.kb
        kb.sync.push_function(func)

        # comments
        comments = { }
        for block in func.blocks:
            for ins_addr in block.instruction_addrs:
                if ins_addr in kb.comments:
                    comments[ins_addr] = kb.comments[ins_addr]
        kb.sync.push_comments(comments)

        # TODO: Fix this
        kb.sync.commit()

    def _on_pullpatches_clicked(self):

        # which user?
        u = self._team_table.selected_user()
        if u is None:
            QMessageBox.critical(None, 'Error',
                                 "Cannot determine which user to pull from. "
                                 "Please select a user in the team table first.")
            return

        kb = self.workspace.instance.project.kb
        # currently we assume all patches are against the main object
        main_object = self.workspace.instance.project.loader.main_object
        patches = kb.sync.pull_patches(user=u)

        patch_added = False
        for patch in patches:
            addr = main_object.mapped_base + patch.offset
            kb.patches.add_patch(addr, patch.new_bytes)
            patch_added = True

        if patch_added:
            # trigger a refresh
            self.workspace.instance.patches.am_event()

            # re-generate the CFG
            # TODO: CFG refinement
            self.workspace.instance.generate_cfg()
