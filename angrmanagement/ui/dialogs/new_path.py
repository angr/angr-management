
from PySide.QtGui import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit
from PySide.QtCore import Qt

from angr import PathHierarchy

from ..widgets import QAddressInput


class NewPath(QDialog):
    def __init__(self, workspace, addr, parent=None):
        super(NewPath, self).__init__(parent)

        # initialization

        self._addr = addr
        self._workspace = workspace

        self._address_box = None
        self._status_label = None
        self._ok_button = None

        self.setWindowTitle('New Path')
        self.setWindowFlags(Qt.WindowStaysOnTopHint)
        self.setWindowModality(Qt.WindowModal)

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

        self.show()

    #
    # Private methods
    #

    def _init_widgets(self):

        # address label

        address_label = QLabel(self)
        address_label.setText('Address')

        address = QAddressInput(None, parent=self, default="%#x" % self._addr)
        self._address_box = address

        address_layout = QHBoxLayout()
        address_layout.addWidget(address_label)
        address_layout.addWidget(address)
        self.main_layout.addLayout(address_layout)

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

        state = inst.project.factory.blank_state(addr=addr)
        hierarchy = PathHierarchy(weakkey_path_mapping=True)
        pg = inst.project.factory.path_group(state, hierarchy=hierarchy)
        inst.path_groups.add_pathgroup(pg=pg)

        symexec_view = self._workspace.views_by_category['symexec'][0]
        symexec_view.select_pathgroup(pg)

        self._workspace.raise_view(symexec_view)

        return True
