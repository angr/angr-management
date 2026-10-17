from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLineEdit, QMessageBox, QPushButton, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.present.types import ParsedTypes, PycParseErrorCls, field_number, field_text, parse_types, set_field

from .set_comment import QCommentTextBox

if TYPE_CHECKING:
    from angr import sim_type


class CTypeEditor(QDialog):
    """
    A dialog to edit C types.

    :param parent:              The parent widget
    :param base_text:           The text to initially display in the editor
    :param multiline:           Whether the editor should be a multiline editor
    :param editing_single:      If set, the name of the single type we are editing

    :ivar list[(Optional[str], SimType)] main_result:
                                The entered types. Will be empty if the dialog was cancelled.
                                Will have only a single entry if editing_single is non-null.
    :ivar list[(Optional[str], SimType)] side_result:
                                Any additional types which were defined along the way.
    """

    def __init__(
        self,
        parent,
        arch,
        base_text: str = "",
        multiline: bool = False,
        editing_single: str | None = None,
        predefined_types=None,
    ) -> None:
        super().__init__(parent)

        self._editing_single = editing_single
        self.arch = arch
        self._predefined_types = predefined_types

        self.text = lambda: ""
        self.setText = lambda x: None
        self._ok_button: QPushButton | None
        self._init_widgets(base_text, multiline)

        self.setWindowTitle("Type editor")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self.main_result: list[tuple[str, sim_type.SimType]] = []
        self.side_result: list[tuple[str, sim_type.SimType]] = []

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
            self.setText = editor.setPlainText

            editor.setPlainText(base_text)
            editor.selectAll()

        else:
            editor = QLineEdit(self)
            editor.setFont(Conf.disasm_font)
            self.text = editor.text
            self.setText = editor.setText
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
        self.close()

    def _on_cancel_pressed(self) -> None:
        self.main_result = []
        self.side_result = []
        self.close()

    def _evaluate(self) -> None:
        parsed = parse_types(self.text(), self.arch, self._predefined_types, self._editing_single)
        assert self._ok_button is not None
        self._ok_button.setEnabled(parsed.ok)
        self.main_result = parsed.main
        self.side_result = parsed.side


def edit_field(ty, field, predefined_types=None) -> bool:
    """Edit member ``field`` (its index or name) of the struct or union ``ty`` in the type editor."""
    fieldno = field_number(ty, field)
    name, text = field_text(ty, fieldno)
    dialog = CTypeEditor(None, ty._arch, text, multiline=False, editing_single=name, predefined_types=predefined_types)
    dialog.exec_()
    changed, warning = set_field(ty, fieldno, ParsedTypes(dialog.main_result))
    if warning is not None:
        QMessageBox.warning(None, "Duplicate field name", warning)
    return changed


__all__ = ["CTypeEditor", "PycParseErrorCls", "edit_field"]
