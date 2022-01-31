from typing import Optional
from collections import OrderedDict

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QDialog, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QDialogButtonBox

import pycparser.plyparser
from angr import sim_type

from .set_comment import QCommentTextBox
from ...config import Conf


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
    def __init__(self, parent, arch, base_text='', multiline=False, allow_multiple=False, predefined_types=None):
        super().__init__(parent)

        self._allow_multiple = allow_multiple
        self.arch = arch
        self._predefined_types = predefined_types

        self.text = lambda: ''
        self._ok_button = None  # type: Optional[QPushButton]
        self._init_widgets(base_text, multiline)

        self.setWindowTitle("Type editor")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.result = []

    def _init_widgets(self, base_text, multiline):
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_pressed)
        buttons.rejected.connect(self._on_cancel_pressed)
        self._ok_button = buttons.button(QDialogButtonBox.Ok)

        if multiline:
            editor = QCommentTextBox(parent=self,
                                     textconfirmed_callback=self._on_ok_pressed,
                                     textchanged_callback=self._evaluate)
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

    def _on_ok_pressed(self):
        if not self.result:
            return

        self.close()

    def _on_cancel_pressed(self):
        self.result = []
        self.close()

    def _evaluate(self):
        text = self.text()

        result = None
        try:
            defs, typedefs = sim_type.parse_file(text, predefined_types=self._predefined_types)
            for k in list(typedefs):
                if k.startswith('struct ') and k[7:] in typedefs:
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

def edit_field(ty, field, predefined_types=None):
    if isinstance(ty, sim_type.SimStruct):
        fields = ty.fields
    elif isinstance(ty, sim_type.SimUnion):
        fields = ty.members
    else:
        raise TypeError("Can't edit a field of a %s" % type(ty))

    if type(fields) is not OrderedDict:
        raise TypeError("Struct or union's fields are of type %s - that's bad" % type(fields))
    fields_list = list(fields.items())

    if type(field) is int:
        if not 0 <= field < len(fields):
            raise IndexError(field)
        fieldno = field
    elif type(field) is str:
        try:
            fieldno = [i for i, (name, _) in fields_list if name == field][0]
        except IndexError:
            raise KeyError(field) from None
    else:
        raise TypeError("Field specifier is a %s - that's bad" % type(field))

    name, subty = fields_list[fieldno]
    text = subty.c_repr(name=name)
    dialog = CTypeEditor(None, ty._arch, text, multiline=False, allow_multiple=False, predefined_types=predefined_types)
    dialog.exec_()
    if not dialog.result:
        return False
    name2, subty = dialog.result[0]
    if name2 is not None:
        if name != name2 and name2 in fields:
            QMessageBox.warning(None, "Duplicate field name", "The name %s is already used" % name2)
        else:
            name = name2
    fields_list[fieldno] = (name, subty)

    if isinstance(ty, sim_type.SimStruct):
        ty.fields = OrderedDict(fields_list)
    elif isinstance(ty, sim_type.SimUnion):
        ty.members = OrderedDict(fields_list)
    else:
        raise TypeError("Can't edit a field of a %s" % type(ty))

    return True
