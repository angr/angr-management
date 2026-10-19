"""The find bar of the terminal views: the query, the mode, the case and regex switches, and the match counter."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from textual.containers import Horizontal
from textual.widgets import Checkbox, Input, Label

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.present.find import FindBarState


class FindTarget(Protocol):
    """What Enter and Shift+Enter in the bar step: the presenter of the view the bar is in."""

    def find_next(self) -> Any: ...

    def find_previous(self) -> Any: ...


class FindBarWidget(Horizontal):
    """The find bar: the query, the mode, case and regex switches, and the match counter."""

    DEFAULT_CSS = """
    FindBarWidget {
        height: 1;
        display: none;
        background: $panel;
    }
    FindBarWidget > Input {
        width: 40;
        height: 1;
        border: none;
        padding: 0 1;
    }
    FindBarWidget > Checkbox {
        height: 1;
        border: none;
        padding: 0;
        margin: 0 1;
    }
    FindBarWidget > Label {
        padding: 0 1;
    }
    """

    def __init__(self, state: FindBarState, on_close: Callable[[], Any]) -> None:
        super().__init__()
        self.state = state
        self.on_close = on_close
        self.query_input = Input(placeholder="Find...", compact=True)
        self.mode_label = Label("", id="find-mode")
        self.case_box = Checkbox("Case", compact=True)
        self.regex_box = Checkbox("Regex", compact=True)
        self.status_label = Label("", id="find-status")
        state.changed.connect(self._update)

    def compose(self) -> ComposeResult:
        yield self.query_input
        yield self.mode_label
        yield self.case_box
        yield self.regex_box
        yield self.status_label

    def _update(self) -> None:
        if not self.is_attached:
            return
        self.display = self.state.is_open
        self.mode_label.update(f"[{self.state.mode}]" if self.state.mode else "")
        self.status_label.update(self.state.status)
        self.case_box.display = self.state.text_options_visible
        self.regex_box.display = self.state.text_options_visible
        if self.query_input.value != self.state.query:
            self.query_input.value = self.state.query

    def open(self) -> None:
        self._update()
        self.query_input.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        event.stop()
        if event.value != self.state.query:
            self.state.set_query(event.value)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        event.stop()
        if event.checkbox is self.case_box:
            self.state.set_case_sensitive(event.value)
        elif event.checkbox is self.regex_box:
            self.state.set_use_regex(event.value)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self.mode_label:
            self.state.next_mode()

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape":
            event.stop()
            self.state.close_bar()
            self.on_close()
        elif event.key == "enter":
            event.stop()
            self.view_presenter().find_next()
        elif event.key == "shift+enter":
            event.stop()
            self.view_presenter().find_previous()
        elif event.key == "ctrl+t":
            event.stop()
            self.state.next_mode()

    def view_presenter(self) -> FindTarget:
        """The presenter of the view the bar is in (a disassembly or a pseudocode view)."""
        parent: Any = self.parent
        return parent.presenter


__all__ = ["FindBarWidget", "FindTarget"]
