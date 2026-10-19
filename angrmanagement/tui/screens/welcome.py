"""
The terminal's Welcome screen, shown at start without a file to open, as the Qt Welcome dialog is: the recent projects
and the Getting Started actions (open a file, the documentation, About).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, OptionList
from textual.widgets.option_list import Option

import angrmanagement
from angrmanagement.config import Conf

from . import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult


class WelcomeScreen(ModalScreen["str | None"]):
    """
    Welcome. Dismisses with what to do: ``"open"`` (Open file...), ``"docs"``, ``"about"``, a recent project's path, or
    None when closed.
    """

    DEFAULT_CSS = (
        dialog_css("WelcomeScreen")
        + """
WelcomeScreen > Vertical { width: 90; }
WelcomeScreen #columns { height: auto; }
WelcomeScreen #recent { width: 1fr; height: 14; }
WelcomeScreen #actions { width: 28; height: auto; padding: 0 0 0 2; }
WelcomeScreen #actions Button { width: 100%; margin: 0 0 1 0; }
WelcomeScreen .group { text-style: bold; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "close", "Close")]

    def __init__(self) -> None:
        super().__init__()
        self.title_text = "Welcome"
        # the most recent first, as the Qt dialog lists them
        self.recent = list(reversed(Conf.recent_files))

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(f"angr management {angrmanagement.__version__}"), classes="title")
            with Horizontal(id="columns"):
                with Vertical(id="recent-pane"):
                    yield Label("Recent Projects", classes="group")
                    yield OptionList(
                        *(Option(Text(os.path.basename(path)), id=str(idx)) for idx, path in enumerate(self.recent)),
                        id="recent",
                    )
                with Vertical(id="actions"):
                    yield Label("Getting Started", classes="group")
                    yield Button("Open file...", id="open")
                    yield Button("Documentation", id="docs")
                    yield Button("About...", id="about")
            with Horizontal(classes="buttons"):
                yield Button("Close", id="close")

    def on_mount(self) -> None:
        target = "#recent" if self.recent else "#open"
        for widget in self.query(target):
            widget.focus()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        index = int(event.option.id or 0)
        self.dismiss(self.recent[index])

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(None if event.button.id == "close" else event.button.id)

    def action_close(self) -> None:
        self.dismiss(None)


def run_welcome_choice(app: Any, choice: str | None) -> None:
    """Do what the user picked on the Welcome screen, as the Qt dialog's buttons do."""
    if choice == "open":
        app.open_file_button()
    elif choice == "docs":
        app.open_doc_link()
    elif choice == "about":
        app.open_about_dialog()
    elif choice:
        app.load_file(choice)


__all__ = ["WelcomeScreen", "run_welcome_choice"]
