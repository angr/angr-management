"""
The status bar: what the current job is doing, for how long, how far along it is, and a button to interrupt it.

:class:`StatusBar` mirrors the Qt status bar: :meth:`~StatusBar.progress` while a job runs,
:meth:`~StatusBar.progress_done` when it ends, and :meth:`~StatusBar.show_message` for a message that clears itself.
"""

from __future__ import annotations

import datetime
import time
from typing import TYPE_CHECKING

from rich.text import Text
from textual.containers import Horizontal
from textual.widgets import ProgressBar, Static

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult
    from textual.timer import Timer

#: A stopwatch appears once a job has run this many seconds, as in the Qt status bar.
STOPWATCH_AFTER = 5


class StatusBar(Horizontal):
    """The status bar at the bottom of the screen."""

    DEFAULT_CSS = """
    StatusBar {
        height: 1;
        width: 100%;
        background: $panel;
    }
    StatusBar > Static {
        width: auto;
        padding: 0 1;
    }
    StatusBar > #status-message {
        width: 1fr;
    }
    StatusBar > #status-interrupt {
        color: $error;
    }
    StatusBar > ProgressBar {
        width: 22;
        padding: 0 1;
    }
    StatusBar > ProgressBar > Bar {
        width: 20;
    }
    StatusBar > #status-caps {
        color: $text-muted;
    }
    """

    def __init__(self, on_interrupt: Callable[[], None] | None = None, caps_text: str = "") -> None:
        super().__init__()
        self.on_interrupt = on_interrupt
        self.caps_text = caps_text
        self._progress_message = ""
        self._progress_percentage = 0.0
        self._stopwatch_start = 0.0
        self._running = False
        self._message_timer: Timer | None = None
        self._temporary_message = ""

    def compose(self) -> ComposeResult:
        yield Static("", id="status-message")
        yield Static("", id="status-progress-text")
        yield Static("", id="status-stopwatch")
        yield Static("", id="status-interrupt")
        yield ProgressBar(total=100, show_eta=False, show_percentage=False, id="status-progress")
        yield Static(Text(self.caps_text), id="status-caps")

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)
        self._show(False)

    def _show(self, running: bool) -> None:
        for widget_id in ("#status-progress-text", "#status-interrupt", "#status-progress"):
            self.query_one(widget_id).display = running
        if not running:
            self.query_one("#status-stopwatch", Static).display = False

    #
    # Progress
    #

    @property
    def status_text(self) -> str:
        return self._progress_message if self._running else self._temporary_message

    def progress(self, status: str, percentage: float, reset_stopwatch: bool = False) -> None:
        self._progress_message = status
        self._progress_percentage = percentage
        if reset_stopwatch or not self._running:
            self._stopwatch_start = time.time()
        self._running = True
        self._refresh()

    def progress_done(self) -> None:
        self._running = False
        self._progress_message = ""
        self.query_one("#status-message", Static).update(Text(self._temporary_message))
        self._show(False)

    def _refresh(self) -> None:
        if not self.is_mounted:
            return
        self._show(self._running)
        if not self._running:
            return
        self.query_one("#status-message", Static).update(Text(self._progress_message))
        self.query_one("#status-progress-text", Static).update(Text(f"{self._progress_percentage:.1f}%"))
        self.query_one("#status-progress", ProgressBar).update(progress=round(self._progress_percentage))
        self.query_one("#status-interrupt", Static).update(Text("✖ interrupt"))
        elapsed = int(time.time() - self._stopwatch_start)
        stopwatch = self.query_one("#status-stopwatch", Static)
        if elapsed > STOPWATCH_AFTER:
            stopwatch.update(Text("⏱ " + str(datetime.timedelta(seconds=elapsed))))
            stopwatch.display = True

    def _tick(self) -> None:
        if self._running:
            self._refresh()

    #
    # Messages
    #

    def show_message(self, text: str, timeout: float = 5) -> None:
        """Show ``text`` for ``timeout`` seconds, unless a job's progress is showing."""
        self._temporary_message = text
        if self._message_timer is not None:
            self._message_timer.stop()
        if not self._running:
            self.query_one("#status-message", Static).update(Text(text))
        if timeout:
            self._message_timer = self.set_timer(timeout, self._clear_message)

    def _clear_message(self) -> None:
        self._temporary_message = ""
        if not self._running:
            self.query_one("#status-message", Static).update("")

    def set_caps_text(self, text: str) -> None:
        self.caps_text = text
        if self.is_mounted:
            self.query_one("#status-caps", Static).update(Text(text))

    def on_click(self, event: events.Click) -> None:
        if event.widget is not None and event.widget.id == "status-interrupt" and self.on_interrupt is not None:
            event.stop()
            self.on_interrupt()
