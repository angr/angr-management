from typing import Optional

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QLineEdit, QDialogButtonBox, QGridLayout, \
    QRadioButton, QButtonGroup

from ...data.breakpoint import Breakpoint, BreakpointType
from ..widgets import QAddressInput


class BreakpointDialog(QDialog):
    """
    Dialog to edit breakpoints.
    """

    def __init__(self, breakpoint_: Breakpoint, workspace: 'Workspace', parent=None):
        super().__init__(parent)
        self.breakpoint = breakpoint_
        self.workspace = workspace
        self.setWindowTitle('Edit Breakpoint')
        self.main_layout: QVBoxLayout = QVBoxLayout()
        self._type_radio_group: Optional[QButtonGroup] = None
        self._address_box: Optional[QAddressInput] = None
        self._size_box: Optional[QLineEdit] = None
        self._comment_box: Optional[QLineEdit] = None
        self._status_label: Optional[QLabel] = None
        self._ok_button: Optional[QPushButton] = None
        self._init_widgets()
        self.setLayout(self.main_layout)
        self._validate()

    #
    # Private methods
    #

    def _init_widgets(self):
        layout = QGridLayout()
        self.main_layout.addLayout(layout)
        self._status_label = QLabel(self)

        row = 0
        layout.addWidget(QLabel('Break on:', self), row, 0, Qt.AlignRight)
        self._type_radio_group = QButtonGroup(self)
        self._type_radio_group.addButton(QRadioButton('Execute', self), BreakpointType.Execute.value)
        self._type_radio_group.addButton(QRadioButton('Write', self), BreakpointType.Write.value)
        self._type_radio_group.addButton(QRadioButton('Read', self), BreakpointType.Read.value)
        for b in self._type_radio_group.buttons():
            layout.addWidget(b, row, 1)
            row += 1

        self._type_radio_group.button(self.breakpoint.type.value).setChecked(True)

        layout.addWidget(QLabel('Address:', self), row, 0, Qt.AlignRight)
        self._address_box = QAddressInput(self._on_address_changed, self.workspace, parent=self,
                                          default=f'{self.breakpoint.addr:#x}')
        layout.addWidget(self._address_box, row, 1)
        row += 1

        layout.addWidget(QLabel('Size:', self), row, 0, Qt.AlignRight)
        self._size_box = QLineEdit(self)
        self._size_box.setText(f'{self.breakpoint.size:#x}')
        self._size_box.textChanged.connect(self._on_size_changed)
        layout.addWidget(self._size_box, row, 1)
        row += 1

        layout.addWidget(QLabel('Comment:', self), row, 0, Qt.AlignRight)
        self._comment_box = QLineEdit(self)
        self._comment_box.setText(self.breakpoint.comment)
        layout.addWidget(self._comment_box, row, 1)
        row += 1

        self.main_layout.addWidget(self._status_label)

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self._ok_button = buttons.button(QDialogButtonBox.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    def _set_valid(self, valid: bool):
        if not valid:
            self._status_label.setText('Invalid')
            self._status_label.setProperty('class', 'status_invalid')
        else:
            self._status_label.setText('Valid')
            self._status_label.setProperty('class', 'status_valid')

        self._ok_button.setEnabled(valid)
        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _get_size(self):
        try:
            return int(self._size_box.text(), 0)
        except ValueError:
            pass
        return None

    #
    # Event handlers
    #


    def _validate(self):
        self._set_valid(bool(self._address_box.target is not None and self._get_size()))

    def _on_address_changed(self, new_text):  # pylint: disable=unused-argument
        self._validate()

    def _on_size_changed(self, new_text):  # pylint: disable=unused-argument
        self._validate()

    def _on_ok_clicked(self):
        self.breakpoint.type = BreakpointType(self._type_radio_group.checkedId())
        self.breakpoint.addr = self._address_box.target
        self.breakpoint.size = self._get_size()
        self.breakpoint.comment = self._comment_box.text()
        self.workspace.instance.breakpoint_mgr.breakpoints.am_event()
        self.accept()
