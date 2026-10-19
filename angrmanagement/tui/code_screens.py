"""
The modal screens of the terminal pseudocode view: rename with the variable's suggested names, retype with the known
type names to complete from, and the multi-line comment editor. Each dismisses with its answer, or None when
cancelled (Escape).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import Button, Input, Label, OptionList, TextArea

from angrmanagement.present.code import is_valid_node_name

from .screens import dialog_css, focus_if_present

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from textual.app import ComposeResult


class RenameScreen(ModalScreen[str | None]):
    """
    A new name, checked as the Qt rename dialog checks it (not blank, no spaces). The variable's candidate names are
    listed below; choosing one puts it in the box.
    """

    DEFAULT_CSS = (
        dialog_css("RenameScreen")
        + "RenameScreen Input { width: 60; } RenameScreen OptionList { height: auto; max-height: 8; width: 60; }"
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, default: str, suggestions: Sequence[str] = ()) -> None:
        super().__init__()
        self.title_text = title
        self.default = default
        self.suggestions = list(suggestions)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Label(Text("New name"))
            yield Input(value=self.default, id="answer")
            yield Label(Text("Suggestions" if self.suggestions else "No suggestions"))
            if self.suggestions:
                yield OptionList(*self.suggestions, id="suggestions")
            yield Label(Text(""), id="status")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        focus_if_present(self, "#answer")
        self._check(self.default)

    def _check(self, text: str) -> bool:
        valid = is_valid_node_name(text)
        self.query_one("#status", Label).update(Text("Valid" if valid else "Invalid"))
        self.query_one("#ok", Button).disabled = not valid
        return valid

    def on_input_changed(self, event: Input.Changed) -> None:
        self._check(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if self._check(event.value):
            self.dismiss(event.value.strip())

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        answer = self.query_one("#answer", Input)
        answer.value = str(event.option.prompt)
        answer.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            value = self.query_one("#answer", Input).value
            if self._check(value):
                self.dismiss(value.strip())
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class RetypeScreen(ModalScreen[str | None]):
    """
    A type, as a declaration (``char *name``) or a type (``char *``). The box completes the names of the types the
    project and the function know; the line under it says whether the text parses, as the Qt retype dialog does.

    :param validate:    Returns whether a text is a type and, if not, why.
    """

    DEFAULT_CSS = dialog_css("RetypeScreen") + "RetypeScreen Input { width: 70; }"
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self, title: str, default: str, type_names: Sequence[str], validate: Callable[[str], tuple[bool, str]]
    ) -> None:
        super().__init__()
        self.title_text = title
        self.default = default
        self.type_names = sorted(set(type_names))
        self.validate = validate

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Label(Text("New type"))
            yield Input(
                value=self.default, id="answer", suggester=SuggestFromList(self.type_names, case_sensitive=True)
            )
            yield Label(Text(""), id="status")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        focus_if_present(self, "#answer")
        self._check(self.default)

    def _check(self, text: str) -> bool:
        valid, reason = self.validate(text)
        self.query_one("#status", Label).update(Text("Valid" if valid else f"Invalid: {reason}"))
        self.query_one("#ok", Button).disabled = not valid
        return valid

    def on_input_changed(self, event: Input.Changed) -> None:
        self._check(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if self._check(event.value):
            self.dismiss(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            value = self.query_one("#answer", Input).value
            if self._check(value):
                self.dismiss(value.strip())
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommentScreen(ModalScreen[str | None]):
    """
    A comment of several lines. Ctrl+Enter confirms, as in the Qt comment dialog; a terminal that cannot report
    Ctrl+Enter (one without the kitty keyboard protocol) has Ctrl+S, and the OK button. The answer is stripped.
    """

    DEFAULT_CSS = dialog_css("CommentScreen") + "CommentScreen TextArea { width: 70; height: 10; }"
    BINDINGS: ClassVar = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+enter", "confirm", "OK", priority=True),
        Binding("ctrl+s", "confirm", "OK", priority=True),
    ]

    def __init__(self, title: str, label: str, text: str = "") -> None:
        super().__init__()
        self.title_text = title
        self.label = label
        self.text = text

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Label(Text(self.label))
            yield TextArea(self.text, id="answer", soft_wrap=False)
            yield Label(Text("Ctrl+Enter (or Ctrl+S) to confirm, Escape to cancel"))
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        area = self.query_one("#answer", TextArea)
        area.focus()
        area.select_all()

    def action_confirm(self) -> None:
        self.dismiss(self.query_one("#answer", TextArea).text.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.action_confirm()
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


__all__ = ["CommentScreen", "RenameScreen", "RetypeScreen"]
