from __future__ import annotations

from collections import OrderedDict

import pycparser.plyparser
from angr import sim_type
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLineEdit, QMessageBox, QPushButton, QVBoxLayout

from angrmanagement.config import Conf

from .set_comment import QCommentTextBox


class CTypeEditor(QDialog):
    """
    A dialog to edit C types.

    :param parent:              The parent widget
    :param base_text:           The text to initially display in the editor
    :param multiline:           Whether the editor should be a multiline editor
    :param allow_multiple:      Whether to allow inputting more than one declaration separated by semicolons

    :ivar list[(Optional[str], SimType)] result:
                                The entered types. Will only be one entry if allow_multiple is false, and will be empty
                                if the dialog was cancelled.
    """

    def __init__(
        self,
        parent,
        arch,
        base_text: str = "",
        multiline: bool = False,
        allow_multiple: bool = False,
        predefined_types=None,
    ) -> None:
        super().__init__(parent)

        self._allow_multiple = allow_multiple
        self.arch = arch
        self._predefined_types = predefined_types

        self.text = lambda: ""
        self._ok_button: QPushButton | None
        self._init_widgets(base_text, multiline)

        self.setWindowTitle("Type editor")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self.result = []

    def _init_widgets(self, base_text, multiline) -> None:
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_pressed)
        buttons.rejected.connect(self._on_cancel_pressed)
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)

        if multiline:
            editor = QCommentTextBox(
                parent=self, textconfirmed_callback=self._on_ok_pressed, textchanged_callback=self._evaluate
            )
            editor.setFont(Conf.disasm_font)
            self.text = editor.toPlainText

            editor.setPlainText(base_text)
            editor.selectAll()

        else:
            editor = QLineEdit(self)
            editor.setFont(Conf.disasm_font)
            self.text = editor.text
            editor.returnPressed.connect(self._on_ok_pressed)
            editor.textChanged.connect(self._evaluate)

            editor.setText(base_text)
            editor.setFocus()
            editor.selectAll()

        layout = QVBoxLayout()
        layout.addWidget(editor)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def _on_ok_pressed(self) -> None:
        if not self.result:
            return

        self.close()

    def _on_cancel_pressed(self) -> None:
        self.result = []
        self.close()

    def _evaluate(self) -> None:
        text = self.text()

        result = None
        try:
            defs, typedefs = sim_type.parse_file(text, predefined_types=self._predefined_types)
            for k in list(typedefs):
                if k.startswith("struct ") and k[7:] in typedefs:
                    typedefs.pop(k)
            result = list(typedefs.items()) + list(defs.items())
            result = [(name, ty.with_arch(self.arch)) for name, ty in result]
        except pycparser.plyparser.ParseError:
            pass

        # hack. idk why our pycparser config will accept `typedef int` as the same as `int`
        if result is None and not text.strip().startswith("typedef"):
            try:
                ty, name = sim_type.parse_type_with_name(text, predefined_types=self._predefined_types)
                result = [(name, ty.with_arch(self.arch))]
            except pycparser.plyparser.ParseError:
                pass

        if not result or (not self._allow_multiple and len(result) != 1):
            self._ok_button.setEnabled(False)
            self.result = []
        else:
            self._ok_button.setEnabled(True)
            self.result = result


def edit_field(ty, field, predefined_types=None) -> bool:
    if isinstance(ty, sim_type.SimStruct):
        fields = ty.fields
    elif isinstance(ty, sim_type.SimUnion):
        fields = ty.members
    else:
        raise TypeError(f"Can't edit a field of a {type(ty)}")

    if type(fields) is not OrderedDict:
        raise TypeError(f"Struct or union's fields are of type {type(fields)} - that's bad")
    fields_list = list(fields.items())

    if isinstance(field, int):
        if not 0 <= field < len(fields):
            raise IndexError(field)
        fieldno = field
    elif isinstance(field, str):
        try:
            fieldno = [i for i, (name, _) in fields_list if name == field][0]
        except IndexError:
            raise KeyError(field) from None
    else:
        raise TypeError(f"Field specifier is a {type(field)} - that's bad")

    name, subty = fields_list[fieldno]
    text = subty.c_repr(name=name)
    dialog = CTypeEditor(None, ty._arch, text, multiline=False, allow_multiple=False, predefined_types=predefined_types)
    dialog.exec_()
    if not dialog.result:
        return False
    name2, subty = dialog.result[0]
    if name2 is not None:
        if name != name2 and name2 in fields:
            QMessageBox.warning(None, "Duplicate field name", f"The name {name2} is already used")
        else:
            name = name2
    fields_list[fieldno] = (name, subty)

    if isinstance(ty, sim_type.SimStruct):
        ty.fields = OrderedDict(fields_list)
    elif isinstance(ty, sim_type.SimUnion):
        ty.members = OrderedDict(fields_list)
    else:
        raise TypeError(f"Can't edit a field of a {type(ty)}")

    return True
