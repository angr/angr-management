"""
Forms: the small dialogs, without a toolkit.

A :class:`Form` is a title, a list of :class:`FormField` rows and the rules the dialog applies while the user types:
:attr:`Form.check` says whether the values can be accepted and what the status line says, and :attr:`Form.on_change`
fills in fields that follow from another (the hook dialog's template, the assembled bytes of a patch). Each frontend
draws a form its own way; code that wants an answer calls :func:`ask_form`, which goes through
``GlobalInfo.ui_services``, and gets the values by key, or None if the user cancelled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from angrmanagement.logic import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

#: What a field can be: a line of text, a hidden line, several lines, several lines of code, a whole number, a check
#: box, a drop-down list, a set of radio buttons, text to read, or a URL to open.
FIELD_KINDS = ("text", "password", "multiline", "code", "int", "bool", "choice", "radio", "label", "link")


@dataclass
class FormField:
    """
    One row of a form.

    :ivar key:          The name of its value in what the form returns.
    :ivar label:        What the row says; empty for none.
    :ivar kind:         One of :data:`FIELD_KINDS`.
    :ivar value:        Its value at the start: a str for text kinds, an int, a bool, or one of the choices' values.
    :ivar choices:      For ``choice`` and ``radio``: (caption, value) pairs.
    :ivar description:  Help shown beside or under the row.
    :ivar readonly:     Whether the user may change it.
    """

    key: str
    label: str
    kind: str = "text"
    value: Any = ""
    choices: Sequence[tuple[str, Any]] = ()
    description: str = ""
    readonly: bool = False

    def __post_init__(self) -> None:
        if self.kind not in FIELD_KINDS:
            raise ValueError(f"Unknown field kind {self.kind!r}")


@dataclass
class FormCheck:
    """
    What a form's check says about the values: whether OK may be pressed, the status line, and values of fields the
    form shows in place of what they held (a field that follows from the others).
    """

    ok: bool
    text: str = ""
    values: dict[str, Any] = field(default_factory=dict)


@dataclass
class FormAction:
    """A button besides OK and Cancel: ``run`` gets the values and returns whether the form closes (as cancelled)."""

    caption: str
    run: Callable[[dict[str, Any]], bool]


@dataclass
class Form:
    """
    A dialog of fields.

    :ivar title:        The window title.
    :ivar fields:       The rows, in order.
    :ivar text:         What the form says above the rows.
    :ivar ok_text:      The caption of the button that accepts.
    :ivar check:        Called with the values whenever one changes; None accepts anything.
    :ivar on_change:    Called with the key of the field that changed and the values; returns the values of other
                        fields to show instead, or None.
    :ivar actions:      Other buttons.
    """

    title: str
    fields: list[FormField]
    text: str = ""
    ok_text: str = "OK"
    check: Callable[[dict[str, Any]], FormCheck] | None = None
    on_change: Callable[[str, dict[str, Any]], dict[str, Any] | None] | None = None
    actions: list[FormAction] = field(default_factory=list)

    def initial_values(self) -> dict[str, Any]:
        return {f.key: f.value for f in self.fields}

    def field_of(self, key: str) -> FormField:
        for f in self.fields:
            if f.key == key:
                return f
        raise KeyError(key)

    def checked(self, values: dict[str, Any]) -> FormCheck:
        """What :attr:`check` says about ``values``; any values are fine without one."""
        return self.check(values) if self.check is not None else FormCheck(True)

    def changed(self, key: str, values: dict[str, Any]) -> dict[str, Any]:
        """The fields to update after ``key`` changed: what :attr:`on_change` and :attr:`check` give."""
        updates: dict[str, Any] = {}
        if self.on_change is not None:
            updates.update(self.on_change(key, values) or {})
        updates.update(self.checked({**values, **updates}).values)
        return updates


def valid_status(ok: bool) -> FormCheck:
    """The Qt dialogs' status line: "Valid" or "Invalid"."""
    return FormCheck(ok, "Valid" if ok else "Invalid")


def ask_form(form: Form, then: Callable[[dict[str, Any] | None], Any]) -> None:
    """Show ``form`` and call ``then`` with its values, or None if the user cancelled, now or once they answer."""
    GlobalInfo.ui_services.ask_form_async(form, then)


__all__ = ["FIELD_KINDS", "Form", "FormAction", "FormCheck", "FormField", "ask_form", "valid_status"]
