from typing import Optional, TYPE_CHECKING

from PySide2.QtGui import Qt
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QDialogButtonBox, QLineEdit

import pycparser

from angr.analyses.decompiler.structured_codegen.c import CVariable, CConstruct
import angr


if TYPE_CHECKING:
    from angrmanagement.ui.views.code_view import CodeView


class TypeBox(QLineEdit):
    """
    Implements a line edit widget for inputting types.
    """
    def __init__(self, textchanged_callback, parent=None):
        super().__init__(parent)

        self.textChanged.connect(textchanged_callback)

    def set_type(self, type_):
        self.setText(repr(type_))

    @property
    def type_str(self):
        text = self.text()
        if self._is_valid_type_str(text):
            return text.strip()
        return None

    @property
    def sim_type(self):
        text = self.text()
        if self._is_valid_type_str(text):
            return angr.sim_type.parse_type(text.strip())
        return None

    @staticmethod
    def _is_valid_type_str(type_str: str):
        try:
            angr.sim_type.parse_type(type_str)
            return True
        except pycparser.c_parser.ParseError:
            return False


class RetypeNode(QDialog):
    """
    A dialog for retyping nodes.
    """
    def __init__(self, code_view: Optional['CodeView']=None, node: Optional[CConstruct]=None, node_type=None,
                 variable=None, parent=None):
        super().__init__(parent)

        # initialization
        self._code_view = code_view
        self._node = node
        self._node_type = node_type
        self._variable = variable

        self.new_type = None

        self._type_box: TypeBox = None
        self._status_label = None
        self._ok_button: QPushButton = None

        self.setWindowTitle('Specify a type')
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):

        # type label

        type_label = QLabel(self)
        type_label.setText('New type')

        type_box = TypeBox(self._on_type_changed, self)
        if self._node is not None:
            if isinstance(self._node, CVariable) and self._node.unified_variable:
                if self._node_type is not None:
                    type_box.set_type(self._node_type)

            type_box.selectAll()
        self._type_box = type_box

        label_layout = QHBoxLayout()
        label_layout.addWidget(type_label)
        label_layout.addWidget(type_box)
        self.main_layout.addLayout(label_layout)

        # status label
        status_label = QLabel(self)
        self.main_layout.addWidget(status_label)
        self._status_label = status_label

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self._on_cancel_clicked)
        self._ok_button = buttons.button(QDialogButtonBox.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_type_changed(self, new_text):  # pylint:disable=unused-argument

        if self._type_box is None:
            # initialization is not done yet
            return

        if self._type_box.type_str is None:
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
        self.new_type = self._type_box.sim_type
        self.close()

    def _on_cancel_clicked(self):
        self.new_type = None
        self.close()
