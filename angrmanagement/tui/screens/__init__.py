"""
Modal screens: what the terminal frontend shows when it asks the user something.

Every screen dismisses with its answer, so ``app.push_screen(screen, callback)`` delivers it; Escape cancels.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Label, Static

if TYPE_CHECKING:
    from collections.abc import Sequence

    from textual.app import ComposeResult
    from textual.screen import Screen

_DIALOG_CSS = """
{name} {{
    align: center middle;
}}
{name} > Vertical {{
    width: auto;
    min-width: 40;
    max-width: 90%;
    height: auto;
    max-height: 90%;
    border: thick $primary;
    background: $surface;
    padding: 0 1;
}}
{name} .title {{
    text-style: bold;
    width: 100%;
    padding: 0 0 1 0;
}}
{name} .body {{
    height: auto;
    max-height: 30;
    width: auto;
}}
{name} .buttons {{
    height: auto;
    width: auto;
    padding: 1 0 0 0;
}}
{name} Button {{
    margin: 0 1 0 0;
    min-width: 8;
}}
"""


def dialog_css(name: str) -> str:
    return _DIALOG_CSS.format(name=name)


_LEVEL_TITLES = {"info": "", "warning": "⚠ ", "critical": "✖ "}


def focus_if_present(screen: Screen, selector: str) -> None:
    """Focus the widget ``selector`` names; a screen the app tears down while it mounts has no children."""
    for widget in screen.query(selector):
        widget.focus()
        return


class MessageScreen(ModalScreen[None]):
    """A notice with an OK button."""

    DEFAULT_CSS = dialog_css("MessageScreen")
    BINDINGS: ClassVar = [Binding("escape", "dismiss_screen", "Close"), Binding("enter", "dismiss_screen", "OK")]

    def __init__(self, level: str, title: str, text: str) -> None:
        super().__init__()
        self.level = level
        self.title_text = title
        self.text = text

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(_LEVEL_TITLES.get(self.level, "") + self.title_text), classes="title")
            with VerticalScroll(classes="body"):
                yield Static(Text(self.text))
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")

    def on_mount(self) -> None:
        focus_if_present(self, "#ok")

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_dismiss_screen(self) -> None:
        self.dismiss(None)


def _escape_answer(buttons: Sequence[str], default: str) -> str:
    for caption in ("Cancel", "No"):
        if caption in buttons:
            return caption
    return default


class QuestionScreen(ModalScreen[str]):
    """A question answered with one of a few buttons."""

    DEFAULT_CSS = dialog_css("QuestionScreen")
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, text: str, buttons: Sequence[str], default: str) -> None:
        super().__init__()
        self.title_text = title
        self.text = text
        self.buttons = list(buttons)
        self.default = default

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            with VerticalScroll(classes="body"):
                yield Static(Text(self.text))
            with Horizontal(classes="buttons"):
                for idx, caption in enumerate(self.buttons):
                    variant = "primary" if caption == self.default else "default"
                    yield Button(caption, id=f"button-{idx}", variant=variant)

    def on_mount(self) -> None:
        if self.default in self.buttons:
            focus_if_present(self, f"#button-{self.buttons.index(self.default)}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(str(event.button.label))

    def action_cancel(self) -> None:
        self.dismiss(_escape_answer(self.buttons, self.default))


class PromptScreen(ModalScreen[str | None]):
    """A line of text; Enter accepts, Escape cancels with None."""

    DEFAULT_CSS = dialog_css("PromptScreen") + "PromptScreen Input { width: 60; }"
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, label: str, default: str = "", password: bool = False) -> None:
        super().__init__()
        self.title_text = title
        self.label = label
        self.default = default
        self.password = password

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            yield Label(Text(self.label))
            yield Input(value=self.default, password=self.password, id="answer")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        focus_if_present(self, "#answer")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self.dismiss(self.query_one("#answer", Input).value)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class FilePickerScreen(ModalScreen[Any]):
    """
    Choose a file or a directory: a directory tree and a path box.

    :param mode:        ``"open"`` (existing files; a list), ``"save"`` (a path) or ``"directory"`` (a directory).
    :param multiple:    In open mode, whether the path box may hold several paths separated by ``;``.
    :param resolve_symlinks:    In directory mode, whether a directory reached through a symbolic link is answered by
                                the path it links to rather than by the link's own path.
    """

    DEFAULT_CSS = (
        dialog_css("FilePickerScreen")
        + """
FilePickerScreen > Vertical { width: 90%; height: 80%; }
FilePickerScreen DirectoryTree { height: 1fr; }
FilePickerScreen Input { width: 100%; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self,
        caption: str,
        directory: str,
        name_filter: str = "",
        mode: str = "open",
        multiple: bool = False,
        resolve_symlinks: bool = False,
    ):
        super().__init__()
        self.caption = caption
        self.mode = mode
        self.multiple = multiple
        self.resolve_symlinks = resolve_symlinks
        self.name_filter = name_filter
        start = directory or os.getcwd()
        self.initial_name = ""
        if not os.path.isdir(start):
            self.initial_name = os.path.basename(start)
            start = os.path.dirname(start) or os.getcwd()
        if not os.path.isdir(start):
            start = os.getcwd()
        self.start_dir = os.path.abspath(start)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.caption), classes="title")
            if self.name_filter:
                yield Label(Text(self.name_filter.replace(";;", "  |  "), style="dim"))
            yield DirectoryTree(self.start_dir, id="tree")
            path = os.path.join(self.start_dir, self.initial_name) if self.initial_name else self.start_dir + os.sep
            yield Input(value=path, id="path")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        focus_if_present(self, "#path")

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.query_one("#path", Input).value = str(event.path)

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.query_one("#path", Input).value = str(event.path) + os.sep

    def on_input_submitted(self, _event: Input.Submitted) -> None:
        self._accept()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self._accept()
        else:
            self.action_cancel()

    def _accept(self) -> None:
        value = self.query_one("#path", Input).value.strip()
        if self.mode == "open":
            paths = [p.strip() for p in value.split(";")] if self.multiple else [value]
            paths = [os.path.expanduser(p) for p in paths if p and os.path.isfile(os.path.expanduser(p))]
            if not paths:
                self.notify("Choose an existing file.", severity="warning")
                return
            self.dismiss(paths)
        elif self.mode == "directory":
            path = os.path.expanduser(value)
            if not os.path.isdir(path):
                self.notify("Choose an existing directory.", severity="warning")
                return
            self.dismiss(os.path.realpath(path) if self.resolve_symlinks else path)
        else:
            path = os.path.expanduser(value)
            if not path or path.endswith(os.sep):
                self.notify("Type a file name.", severity="warning")
                return
            self.dismiss(path)

    def action_cancel(self) -> None:
        self.dismiss([] if self.mode == "open" else None)
