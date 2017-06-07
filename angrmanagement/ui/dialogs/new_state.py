
from PySide.QtGui import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QGroupBox, QGridLayout, QComboBox, \
    QLineEdit, QTextEdit
from PySide.QtCore import Qt
import pyqode.core.api
import pyqode.core.modes

from angr import PathHierarchy

from ..widgets import QAddressInput, QStateComboBox
from ...data.states import StateRecord
from ...utils.namegen import NameGenerator


class NewState(QDialog):

    INITIAL_INIT_CODE = "def init_state(state):\n    return state"

    def __init__(self, workspace, parent=None):
        super(NewState, self).__init__(parent)

        # initialization

        self.state_record = None  # output

        self._workspace = workspace

        self._name_edit = None  # type: QLineEdit
        self._base_state_combo = None  # type: QStateComboBox
        self._mode_combo = None  # type: QComboBox
        self._editor = None  # type: QTextEdit
        self._ok_button = None

        self.setWindowTitle('New State')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):

        layout = QGridLayout()

        row = 0

        # name

        name_label = QLabel(self)
        name_label.setText("Name")

        txt_name = QLineEdit(self)
        txt_name.setText(NameGenerator.random_name())
        self._name_edit = txt_name

        layout.addWidget(name_label, row, 0)
        layout.addWidget(txt_name, row, 1)
        row += 1

        # base state

        state_label = QLabel(self)
        state_label.setText('Base state')

        base_state_combo = QStateComboBox(self._workspace.instance.states, self)
        self._base_state_combo = base_state_combo

        layout.addWidget(state_label, row, 0)
        layout.addWidget(base_state_combo, row, 1)
        row += 1

        # mode

        mode_label = QLabel(self)
        mode_label.setText("Mode")

        mode_combo = QComboBox(self)
        mode_combo.addItem("Symbolic", "symbolic")
        mode_combo.addItem("Static", "static")
        mode_combo.addItem("Fast-path", "fastpath")
        self._mode_combo = mode_combo

        layout.addWidget(mode_label, row, 0)
        layout.addWidget(mode_combo, row, 1)
        row += 1

        # custom code

        code_label = QLabel(self)
        code_label.setText('Initialization code')

        self._editor = pyqode.core.api.CodeEdit()
        self._editor.modes.append(pyqode.core.modes.PygmentsSyntaxHighlighter(self._editor.document()))
        self._editor.modes.append(pyqode.core.modes.CaretLineHighlighterMode())

        self._editor.insertPlainText(self.INITIAL_INIT_CODE)

        layout.addWidget(code_label, row, 0)
        layout.addWidget(self._editor, row, 1)
        row += 1

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
        if self._new_state():
            self.close()

    def _on_cancel_clicked(self):
        self.close()

    #
    # Private methods
    #

    def _new_state(self):

        # name
        name = self._name_edit.text()
        if not name:
            return False

        if name in self._workspace.instance.states:
            return False

        # base state
        base = self._base_state_combo.state_record

        # mode
        if self._mode_combo.currentIndex() == -1:
            return False

        mode = self._mode_combo.itemData(self._mode_combo.currentIndex())

        # custom code
        code = self._editor.toPlainText()
        if code == self.INITIAL_INIT_CODE:
            code = None

        self.state_record = StateRecord(name, base, False, mode, custom_code=code)

        self._workspace.instance.states[name] = self.state_record

        return True
