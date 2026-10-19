"""
The file bar of the terminal frontend, the Qt File toolbar: Open (load a new binary) and Save (save the angr
database), the same two actions as the File menu.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.containers import Horizontal
from textual.widgets import Button

if TYPE_CHECKING:
    from textual.app import ComposeResult

#: The buttons: id, label, the Qt toolbar's tooltip, and the app method both frontends name the action by.
FILE_ACTIONS = (
    ("file-open", "Open", "Open a new file for analysis", "open_file_button"),
    ("file-save", "Save", "Save angr database", "save_database"),
)


class FileBar(Horizontal):
    """The File toolbar: Open and Save."""

    DEFAULT_CSS = """
    FileBar {
        height: 1;
        width: auto;
    }
    FileBar > Button {
        min-width: 4;
        margin: 0 1 0 0;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:  # pylint: disable=redefined-builtin
        super().__init__(id=id)
        self.buttons = {
            name: Button(label, id=name, compact=True, tooltip=tooltip) for name, label, tooltip, _ in FILE_ACTIONS
        }

    def compose(self) -> ComposeResult:
        yield from self.buttons.values()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        action = next((method for name, _, _, method in FILE_ACTIONS if name == event.button.id), None)
        if action is None:
            return
        event.stop()
        getattr(self.app, action)()


__all__ = ["FILE_ACTIONS", "FileBar"]
