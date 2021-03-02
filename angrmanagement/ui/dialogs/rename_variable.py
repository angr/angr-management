from typing import Optional, TYPE_CHECKING

from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit
from PySide2.QtCore import Qt

if TYPE_CHECKING:
    from angrmanagement.ui.views.disassembly_view import DisassemblyView
    from angrmanagement.ui.views.code_view import CodeView
    from angr.analyses.decompiler.structured_codegen import CVariable


class VariableNameBox(QLineEdit):
    def __init__(self, textchanged_callback, parent=None):
        super(VariableNameBox, self).__init__(parent)

        self.textChanged.connect(textchanged_callback)

    @property
    def name(self):
        text = self.text()
        if self._is_valid_variable_name(text):
            return text.strip()
        return None

    def _is_valid_variable_name(self, input):
        return input and not (' ' in input.strip())


class RenameVariable(QDialog):
    def __init__(self, disasm_view: Optional['DisassemblyView']=None, code_view: Optional['CodeView']=None,
                 cvariable: Optional['CVariable']=None, parent=None):
        super(RenameVariable, self).__init__(parent)

        # initialization
        self._disasm_view = disasm_view
        self._code_view = code_view
        self._cvariable = cvariable

        self._name_box = None
        self._status_label = None
        self._ok_button = None

        self.setWindowTitle('Rename Variable')

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):

        # name label

        name_label = QLabel(self)
        name_label.setText('New name')

        name_box = VariableNameBox(self._on_name_changed, self)
        if self._cvariable is not None and self._cvariable.unified_variable.name:
            name_box.setText(self._cvariable.unified_variable.name)
            name_box.selectAll()
        self._name_box = name_box

        label_layout = QHBoxLayout()
        label_layout.addWidget(name_label)
        label_layout.addWidget(name_box)
        self.main_layout.addLayout(label_layout)

        # status label
        status_label = QLabel(self)
        self.main_layout.addWidget(status_label)
        self._status_label = status_label

        # buttons

        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.setEnabled(False)
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

    def _on_name_changed(self, new_text):

        if self._name_box is None:
            # initialization is not done yet
            return

        if self._name_box.name is None:
            # the variable name is invalid
            self._status_label.setText('Invalid')
            self._status_label.setProperty('class', 'status_invalid')
            self._ok_button.setEnabled(False)
        else:
            self._status_label.setText('Valid')
            self._status_label.setProperty('class', 'status_valid')
            self._ok_button.setEnabled(True)

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self):
        varname = self._name_box.name
        if varname is not None:
            if self._code_view is not None and self._cvariable is not None:
                self._cvariable.unified_variable.name = varname
                self._code_view.refresh_text()
                self.close()

    def _on_cancel_clicked(self):
        self.cfg_args = None
        self.close()
