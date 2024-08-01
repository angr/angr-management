from __future__ import annotations

from typing import TYPE_CHECKING, Any

import angr
import pycparser
from angr.analyses.decompiler.structured_codegen.c import CConstruct, CFunction, CVariable
from angr.sim_variable import SimVariable
from PySide6.QtCore import QSize
from PySide6.QtGui import QFont, Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from angr.sim_type import SimType

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.code_view import CodeView


class TypeBox(QLineEdit):
    """
    Implements a line edit widget for inputting types.
    """

    def __init__(self, textchanged_callback, predefined_types=None, parent=None) -> None:
        super().__init__(parent)

        self._cvariable: CVariable | None = None
        self._predefined_types = predefined_types

        self.textChanged.connect(textchanged_callback)
        self.setFont(QFont(Conf.disasm_font))

    def set_type(self, type_: SimType, cvariable: CVariable = None) -> None:
        self._cvariable = cvariable
        if cvariable is not None and isinstance(cvariable.unified_variable, SimVariable):
            type_str = type_.c_repr(name=cvariable.unified_variable.name)
        else:
            type_str = type_.c_repr(name="foobar")
        self.setText(type_str)

    @property
    def type_str(self):
        text = self.text()
        valid, _ = self._is_valid_type_str(text)
        if valid:
            return text.strip()
        return None

    @property
    def sim_type(self):
        text = self.text()
        valid, parsed_type = self._is_valid_type_str(text)
        if valid:
            return parsed_type
        return None

    def _is_valid_type_str(self, type_str: str) -> tuple[bool, SimType | None]:
        """
        We accept two forms of type strings. The user can either specify a full variable declaration, like "char var",
        or only specify a type string, like "char". This method first attempts to parse the string as a variable
        declaration, and when it fails, it will parse the string as a pure type string.
        """

        # parse as a variable declaration
        declaration = type_str
        if not declaration.endswith(";"):
            declaration += ";"
        try:
            defns = angr.sim_type.parse_defns(declaration, predefined_types=self._predefined_types)
        except pycparser.c_parser.ParseError:
            defns = {}
        if len(defns) == 1:
            return True, next(iter(defns.values()))

        try:
            parsed_type = angr.sim_type.parse_type(type_str, predefined_types=self._predefined_types)
            return True, parsed_type
        except pycparser.c_parser.ParseError:
            return False, None


class RetypeNode(QDialog):
    """
    A dialog for retyping nodes.
    """

    def __init__(
        self,
        instance: Instance,
        code_view: CodeView | None = None,
        node: CConstruct | None = None,
        node_type=None,
        variable=None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        # initialization
        self._instance = instance
        self._code_view = code_view
        self._node = node
        self._node_type = node_type
        self._variable = variable

        self.new_type = None

        self._type_box: TypeBox = None
        self._status_label = None
        self._ok_button: QPushButton = None

        self.setWindowTitle("Specify a type")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        self.setLayout(self.main_layout)

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(600, 50)

    #
    # Private methods
    #

    def _get_predefined_types(self) -> dict[Any, SimType]:
        # global types
        r = dict(self._instance.kb.types)
        # local types
        if not self._code_view.function.am_none:
            func_addr = self._code_view.function.addr
            if (func_addr, "pseudocode") in self._instance.kb.structured_code:
                pseudocode_cache = self._instance.kb.structured_code[(func_addr, "pseudocode")]
                r.update(pseudocode_cache.local_types)
        return r

    def _init_widgets(self) -> None:
        # Type label

        type_label = QLabel(self)
        type_label.setText("New type")

        type_box = TypeBox(self._on_type_changed, predefined_types=self._get_predefined_types(), parent=self)
        if self._node is not None:
            if isinstance(self._node, CVariable) and self._node.unified_variable and self._node_type is not None:
                type_box.set_type(self._node_type, cvariable=self._node)
            elif isinstance(self._node, CFunction):
                type_box.setText(self._node.functy.c_repr(name=self._node.demangled_name, full=True, name_parens=False))

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
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_type_changed(self, new_text) -> None:  # pylint:disable=unused-argument
        if self._type_box is None:
            # initialization is not done yet
            return

        if self._type_box.type_str is None:
            # the variable name is invalid
            self._status_label.setText("Invalid")
            self._status_label.setProperty("class", "status_invalid")
            self._ok_button.setEnabled(False)
        else:
            self._status_label.setText("Valid")
            self._status_label.setProperty("class", "status_valid")
            self._ok_button.setEnabled(True)

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self) -> None:
        self.new_type = self._type_box.sim_type
        self.close()

    def _on_cancel_clicked(self) -> None:
        self.new_type = None
        self.close()
