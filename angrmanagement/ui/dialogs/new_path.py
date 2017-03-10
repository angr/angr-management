
from PySide.QtGui import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QGroupBox, QGridLayout
from PySide.QtCore import Qt

from angr import PathHierarchy

from ..widgets import QAddressInput, QStateComboBox


class NewPath(QDialog):
    def __init__(self, workspace, addr, parent=None):
        super(NewPath, self).__init__(parent)

        # initialization

        self._addr = addr
        self._workspace = workspace

        self._address_box = None
        self._status_label = None
        self._init_state_combo = None
        self._ok_button = None

        self.setWindowTitle('New Path')
        self.setWindowFlags(Qt.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModal)

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

        # self.show()

    #
    # Private methods
    #

    def _init_widgets(self):

        layout = QGridLayout()

        # address label

        address_label = QLabel(self)
        address_label.setText('Address')

        address = QAddressInput(None, parent=self, default="%#x" % self._addr)
        self._address_box = address

        layout.addWidget(address_label, 0, 0)
        layout.addWidget(address, 0, 1)

        # initial state

        state_label = QLabel(self)
        state_label.setText('Initial state')

        init_state_combo = QStateComboBox(self._workspace.instance.states, self)
        self._init_state_combo = init_state_combo

        layout.addWidget(state_label, 1, 0)
        layout.addWidget(init_state_combo, 1, 1)

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.clicked.connect(self._on_ok_clicked)
        self._ok_button = ok_button

        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(layout)
        self.main_layout.addLayout(buttons_layout)

    #
    # Event handlers
    #

    def _on_address_changed(self, new_text):
        if new_text.strip():
            self._ok_button.setEnabled(True)
        else:
            self._ok_button.setEnabled(False)

    def _on_ok_clicked(self):

        self._addr = self._address_box.raw_target

        if self._addr is None:
            return

        if self._new_path(self._addr):
            self.close()

    def _on_cancel_clicked(self):
        self.cfg_args = None
        self.close()

    #
    # Private methods
    #

    def _new_path(self, addr):
        inst = self._workspace.instance

        state_record = self._init_state_combo.state_record
        if state_record is None:
            return False

        state = state_record.state(inst.project, address=addr)
        hierarchy = PathHierarchy(weakkey_path_mapping=True)
        pg = inst.project.factory.path_group(state, hierarchy=hierarchy)
        inst.path_groups.add_pathgroup(pg=pg)

        symexec_view = self._workspace.views_by_category['symexec'][0]
        symexec_view.select_pathgroup(pg)

        self._workspace.raise_view(symexec_view)

        return True
