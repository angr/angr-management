"""The Qt form dialog: a :class:`~angrmanagement.present.forms.Form` as a QDialog."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from angrmanagement.present.forms import Form, FormCheck, FormField


class FormDialog(QDialog):
    """A form; :attr:`values` holds what the user accepted, or None."""

    def __init__(self, form: Form, parent=None) -> None:
        super().__init__(parent)
        self.form = form
        self.values: dict[str, Any] | None = None
        self._current: dict[str, Any] = form.initial_values()
        self._editors: dict[str, Any] = {}
        self._updating = False
        self.setWindowTitle(form.title)
        self._init_widgets()
        self._show_check(form.checked(self._current))

    def _init_widgets(self) -> None:
        layout = QVBoxLayout(self)
        if self.form.text:
            text = QLabel(self.form.text, self)
            text.setWordWrap(True)
            layout.addWidget(text)
        rows = QFormLayout()
        for f in self.form.fields:
            editor = self._editor(f)
            self._editors[f.key] = editor
            widget = editor[0] if isinstance(editor, tuple) else editor
            if f.description:
                widget.setToolTip(f.description)
            rows.addRow(f.label, widget)
        layout.addLayout(rows)
        self._status = QLabel(self)
        layout.addWidget(self._status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self)
        self._ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok.setText(self.form.ok_text)
        for action in self.form.actions:
            button = QPushButton(action.caption, self)
            button.clicked.connect(lambda _=False, action=action: self._run_action(action))
            buttons.addButton(button, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _editor(self, f: FormField) -> Any:
        kind = f.kind
        if kind in ("text", "password"):
            editor = QLineEdit(str(f.value), self)
            if kind == "password":
                editor.setEchoMode(QLineEdit.EchoMode.Password)
            editor.textChanged.connect(lambda _t, key=f.key: self._changed(key))
        elif kind == "int":
            editor = QSpinBox(self)
            editor.setRange(-(2**31), 2**31 - 1)
            editor.setValue(int(f.value or 0))
            editor.valueChanged.connect(lambda _v, key=f.key: self._changed(key))
        elif kind in ("multiline", "code"):
            editor = QPlainTextEdit(str(f.value), self)
            if kind == "code":
                editor.setFont(Conf.disasm_font)
            editor.textChanged.connect(lambda key=f.key: self._changed(key))
        elif kind == "bool":
            editor = QCheckBox(self)
            editor.setChecked(bool(f.value))
            editor.toggled.connect(lambda _c, key=f.key: self._changed(key))
        elif kind == "choice":
            editor = QComboBox(self)
            for caption, _value in f.choices:
                editor.addItem(caption)
            values = [value for _caption, value in f.choices]
            if f.value in values:
                editor.setCurrentIndex(values.index(f.value))
            editor.currentIndexChanged.connect(lambda _i, key=f.key: self._changed(key))
        elif kind == "radio":
            box = QWidget(self)
            box_layout = QHBoxLayout(box)
            box_layout.setContentsMargins(0, 0, 0, 0)
            group = QButtonGroup(box)
            for idx, (caption, value) in enumerate(f.choices):
                button = QRadioButton(caption, box)
                button.setChecked(value == f.value)
                group.addButton(button, idx)
                box_layout.addWidget(button)
            group.idToggled.connect(lambda _i, on, key=f.key: on and self._changed(key))
            editor = (box, group)
        else:
            editor = QLabel(str(f.value), self)
            editor.setWordWrap(True)
        widget = editor[0] if isinstance(editor, tuple) else editor
        widget.setEnabled(not f.readonly or kind == "label")
        return editor

    def _value_of(self, key: str) -> Any:
        f = self.form.field_of(key)
        editor = self._editors[key]
        if isinstance(editor, tuple):
            idx = editor[1].checkedId()
            return f.choices[idx][1] if 0 <= idx < len(f.choices) else None
        if isinstance(editor, QLineEdit):
            return editor.text()
        if isinstance(editor, QSpinBox):
            return editor.value()
        if isinstance(editor, QPlainTextEdit):
            return editor.toPlainText()
        if isinstance(editor, QCheckBox):
            return editor.isChecked()
        if isinstance(editor, QComboBox):
            idx = editor.currentIndex()
            return f.choices[idx][1] if 0 <= idx < len(f.choices) else None
        return self._current.get(key)

    def _set_value(self, key: str, value: Any) -> None:
        f = self.form.field_of(key)
        editor = self._editors[key]
        self._current[key] = value
        self._updating = True
        try:
            values = [v for _c, v in f.choices]
            if isinstance(editor, tuple):
                if value in values:
                    editor[1].button(values.index(value)).setChecked(True)
            elif isinstance(editor, (QLineEdit, QLabel)):
                editor.setText(str(value))
            elif isinstance(editor, QSpinBox):
                editor.setValue(int(value or 0))
            elif isinstance(editor, QPlainTextEdit):
                editor.setPlainText(str(value))
            elif isinstance(editor, QCheckBox):
                editor.setChecked(bool(value))
            elif isinstance(editor, QComboBox) and value in values:
                editor.setCurrentIndex(values.index(value))
        finally:
            self._updating = False

    def _changed(self, key: str) -> None:
        if self._updating:
            return
        self._current[key] = self._value_of(key)
        for other, value in self.form.changed(key, dict(self._current)).items():
            if other != key and value != self._current.get(other):
                self._set_value(other, value)
        self._show_check(self.form.checked(self._current))

    def _show_check(self, check: FormCheck) -> None:
        for other, value in check.values.items():
            if value != self._current.get(other):
                self._set_value(other, value)
        self._status.setText(check.text)
        self._status.setVisible(bool(check.text))
        self._status.setProperty("class", "status_valid" if check.ok else "status_invalid")
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)
        self._ok.setEnabled(check.ok)

    def _run_action(self, action) -> None:
        if action.run(dict(self._current)):
            self.reject()

    def _accept(self) -> None:
        check = self.form.checked(self._current)
        if not check.ok:
            self._show_check(check)
            return
        self.values = {**self._current, **check.values}
        self.accept()


__all__ = ["FormDialog"]
