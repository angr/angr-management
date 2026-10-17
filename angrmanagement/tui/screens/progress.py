"""
The terminal's progress screen for a blocking job, as the Qt main window's ProgressDialog: the job's text, a progress
bar and Cancel, which interrupts the job. The status bar shows the progress of every other job.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label, ProgressBar

from . import dialog_css

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual.app import ComposeResult


class ProgressScreen(ModalScreen[None]):
    """The progress of a blocking job; the app dismisses it when the job finishes."""

    DEFAULT_CSS = dialog_css("ProgressScreen") + "ProgressScreen ProgressBar { width: 60; }"
    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, text: str, cancel: Callable[[], None]) -> None:
        super().__init__()
        self.title_text = "Progress"
        self.text = text
        self.cancel = cancel

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(Text(self.text), id="progress-text")
            yield ProgressBar(total=100, show_eta=False, id="bar")
            with Horizontal(classes="buttons"):
                yield Button("Cancel", id="cancel")

    def update_progress(self, text: str, percentage: float) -> None:
        self.text = text
        for label in self.query("#progress-text"):
            label.update(Text(text))  # type: ignore[attr-defined]
        for bar in self.query("#bar"):
            bar.update(progress=round(percentage))  # type: ignore[attr-defined]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    def action_cancel(self) -> None:
        # the job stops; the app takes the screen down when it finishes
        self.cancel()


__all__ = ["ProgressScreen"]
