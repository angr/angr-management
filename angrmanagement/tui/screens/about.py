"""The terminal's About screen: the logo (a picture on a tier 3 terminal), the version and the credits link."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

import angrmanagement
from angrmanagement.consts import IMG_LOCATION
from angrmanagement.tui.widgets.picture import picture

from . import dialog_css

if TYPE_CHECKING:
    from textual.app import ComposeResult

#: the picture the Qt About dialog shows
LOGO = os.path.join(IMG_LOCATION, "angr-ds.png")
CREDITS_URL = "http://angr.io/"

#: the logo where the terminal draws no pictures
BANNER = r"""
  __ _ _ __   __ _ _ __
 / _` | '_ \ / _` | '__|
| (_| | | | | (_| | |
 \__,_|_| |_|\__, |_|
             |___/
"""


class AboutScreen(ModalScreen[None]):
    """About angr management."""

    DEFAULT_CSS = (
        dialog_css("AboutScreen")
        + """
AboutScreen #logo { width: 28; height: 10; }
AboutScreen .facts { padding: 0 0 0 2; width: auto; height: auto; }
AboutScreen .name { text-style: bold; }
"""
    )
    BINDINGS: ClassVar = [Binding("escape", "close", "Close"), Binding("enter", "close", "Close", show=False)]

    def __init__(self, caps: Any = None) -> None:
        super().__init__()
        self.title_text = "About"
        self.caps = caps

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.title_text), classes="title")
            with Horizontal(classes="body"):
                yield picture(LOGO, self.caps, lambda: Static(Text(BANNER, style="bold")), id="logo")
                with Vertical(classes="facts"):
                    yield Label(Text("angr management"), classes="name")
                    yield Label(Text("Version: " + angrmanagement.__version__, style="bold"), id="version")
                    yield Label(Text("Credits", style=f"bold link {CREDITS_URL}"), id="credits")
            with Horizontal(classes="buttons"):
                yield Button("OK", id="ok", variant="primary")

    def on_mount(self) -> None:
        for button in self.query("#ok"):
            button.focus()

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


__all__ = ["AboutScreen"]
