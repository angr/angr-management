"""
The terminal's form screen: a :class:`~angrmanagement.present.forms.Form` as a modal screen.

Each field is a row: a label and an editor (an input line, a text area, a check box, a drop-down list, radio buttons,
or text to read). The form's check runs whenever a value changes and its verdict goes in the status line; OK is
disabled while the values cannot be accepted. Enter in a line, Ctrl+Enter or Ctrl+S accept; Escape cancels.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, RadioButton, RadioSet, Select, Static, TextArea

from . import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult
    from textual.widget import Widget

    from angrmanagement.present.forms import Form, FormField


class FormScreen(ModalScreen["dict[str, Any] | None"]):
    """A form; dismisses with its values by key, or None if cancelled."""

    DEFAULT_CSS = (
        dialog_css("FormScreen")
        + """
FormScreen > Vertical { min-width: 60; }
FormScreen .row { height: auto; width: auto; }
FormScreen .row > .field-label { width: 18; padding: 0 1 0 0; }
FormScreen .row Input { width: 60; }
FormScreen .row Select { width: 60; }
FormScreen .row TextArea { width: 80; height: 12; }
FormScreen .row .field-text { width: 80; height: auto; }
FormScreen .row RadioSet { width: 60; height: auto; }
FormScreen .description { color: $text-muted; padding: 0 0 0 18; }
FormScreen #status { height: auto; padding: 1 0 0 0; }
FormScreen #status.invalid { color: $error; }
FormScreen .fields { height: auto; max-height: 40; }
"""
    )
    BINDINGS: ClassVar = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "accept", "OK", show=False),
        Binding("ctrl+enter", "accept", "OK", show=False),
    ]

    def __init__(self, form: Form) -> None:
        super().__init__()
        self.form = form
        self.values: dict[str, Any] = form.initial_values()
        #: the editor of each field's key
        self.editors: dict[str, Widget] = {}
        self._updating = False
        self._ok = True

    #
    # Building
    #

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.form.title), classes="title")
            if self.form.text:
                yield Static(Text(self.form.text))
            with VerticalScroll(classes="fields"):
                for f in self.form.fields:
                    editor = self._editor(f)
                    self.editors[f.key] = editor
                    if f.label:
                        with Horizontal(classes="row"):
                            yield Label(Text(f.label), classes="field-label")
                            yield editor
                    else:
                        with Horizontal(classes="row"):
                            yield editor
                    if f.description:
                        yield Static(Text(f.description), classes="description")
            yield Static("", id="status")
            with Horizontal(classes="buttons"):
                yield Button(self.form.ok_text, id="ok", variant="primary")
                for idx, action in enumerate(self.form.actions):
                    yield Button(action.caption, id=f"action-{idx}")
                yield Button("Cancel", id="cancel")

    @staticmethod
    def _editor(f: FormField) -> Widget:
        kind = f.kind
        widget: Widget
        if kind in ("text", "password"):
            widget = Input(str(f.value), password=kind == "password", compact=True, select_on_focus=False)
        elif kind == "int":
            widget = Input(str(f.value), type="integer", compact=True)
        elif kind in ("multiline", "code"):
            widget = TextArea(
                str(f.value),
                soft_wrap=kind == "multiline",
                show_line_numbers=kind == "code",
                tab_behavior="indent" if kind == "code" else "focus",
            )
        elif kind == "bool":
            widget = Checkbox("", bool(f.value), compact=True)
        elif kind == "choice":
            options = [(caption, idx) for idx, (caption, _value) in enumerate(f.choices)]
            values = [value for _caption, value in f.choices]
            selected = values.index(f.value) if f.value in values else Select.NULL
            widget = Select(options, value=selected, allow_blank=selected is Select.NULL, compact=True)
        elif kind == "radio":
            widget = RadioSet(
                *(RadioButton(caption, value=value == f.value) for caption, value in f.choices),
                compact=True,
            )
        elif kind == "link":
            # an OSC 8 hyperlink the terminal opens
            widget = Static(Text(str(f.value), style=f"link {f.value}" if f.value else ""), classes="field-text")
        else:
            widget = Static(Text(str(f.value)), classes="field-text")
        widget.disabled = f.readonly and kind not in ("label", "link")
        if f.description:
            widget.tooltip = f.description
        return widget

    def on_mount(self) -> None:
        self._refresh_status(self.form.checked(self.values))
        for f in self.form.fields:
            if not f.readonly and f.kind != "label":
                with contextlib.suppress(Exception):
                    self.editors[f.key].focus()
                return
        with contextlib.suppress(Exception):
            self.query_one("#ok", Button).focus()

    #
    # Values
    #

    def value_of(self, key: str) -> Any:
        """What the editor of ``key`` holds, as the form takes it."""
        f = self.form.field_of(key)
        editor = self.editors[key]
        if isinstance(editor, Input):
            if f.kind == "int":
                try:
                    return int(editor.value, 0)
                except ValueError:
                    return None
            return editor.value
        if isinstance(editor, TextArea):
            return editor.text
        if isinstance(editor, Checkbox):
            return editor.value
        if isinstance(editor, Select):
            idx = editor.value
            return f.choices[idx][1] if isinstance(idx, int) and 0 <= idx < len(f.choices) else None
        if isinstance(editor, RadioSet):
            idx = editor.pressed_index
            return f.choices[idx][1] if 0 <= idx < len(f.choices) else None
        return self.values.get(key)

    def set_value(self, key: str, value: Any) -> None:
        """Show ``value`` in the editor of ``key`` without running the form's rules."""
        f = self.form.field_of(key)
        editor = self.editors[key]
        self.values[key] = value
        self._updating = True
        try:
            if isinstance(editor, Input):
                editor.value = str(value)
            elif isinstance(editor, TextArea):
                editor.load_text(str(value))
            elif isinstance(editor, Checkbox):
                editor.value = bool(value)
            elif isinstance(editor, Select):
                values = [v for _c, v in f.choices]
                if value in values:
                    editor.value = values.index(value)
            elif isinstance(editor, RadioSet):
                values = [v for _c, v in f.choices]
                if value in values:
                    buttons = list(editor.query(RadioButton))
                    buttons[values.index(value)].value = True
            elif isinstance(editor, Static):
                editor.update(Text(str(value)))
        finally:
            self._updating = False

    def _key_of(self, widget: Any) -> str | None:
        for key, editor in self.editors.items():
            if editor is widget:
                return key
        return None

    def _changed(self, widget: Any) -> None:
        if self._updating:
            return
        key = self._key_of(widget)
        if key is None:
            return
        self.values[key] = self.value_of(key)
        updates = self.form.changed(key, dict(self.values))
        for other, value in updates.items():
            if other != key and value != self.values.get(other):
                self.set_value(other, value)
        self._refresh_status(self.form.checked(self.values))

    def _refresh_status(self, check: Any) -> None:
        self._ok = check.ok
        if not self.is_mounted:
            return
        for other, value in check.values.items():
            if value != self.values.get(other):
                self.set_value(other, value)
        status = self.query_one("#status", Static)
        status.update(Text(check.text))
        status.display = bool(check.text)
        status.set_class(not check.ok, "invalid")
        self.query_one("#ok", Button).disabled = not check.ok

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        self._changed(event.input)

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        event.stop()
        self._changed(event.text_area)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        self._changed(event.checkbox)

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        self._changed(event.select)

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        event.stop()
        self._changed(event.radio_set)

    #
    # Answers
    #

    def on_input_submitted(self, event: Input.Submitted) -> None:
        event.stop()
        self.action_accept()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        button_id = event.button.id or ""
        if button_id == "ok":
            self.action_accept()
        elif button_id == "cancel":
            self.action_cancel()
        elif button_id.startswith("action-"):
            action = self.form.actions[int(button_id.removeprefix("action-"))]
            if action.run(dict(self.values)):
                self.dismiss(None)

    def action_accept(self) -> None:
        for key in self.editors:
            self.values[key] = self.value_of(key)
        check = self.form.checked(self.values)
        if not check.ok:
            self._refresh_status(check)
            return
        self.dismiss({**self.values, **check.values})

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = ["FormScreen"]
