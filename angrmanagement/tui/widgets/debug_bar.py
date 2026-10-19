"""
The debug bar of the terminal frontend, the Qt debug toolbar in one row: continue backward, step backward, continue
(halt while the debugger runs), step, step over, the launch menu (a new simulation or a new trace debugger), stop,
the debugger selector and the debugger's state. Each button is enabled when the current debugger says it can.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.containers import Horizontal
from textual.widgets import Button, Label, Select

from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.present.debug_bar import DEBUG_ACTIONS, DebugBarPresenter

if TYPE_CHECKING:
    from textual.app import ComposeResult

#: The buttons' labels, for the Qt toolbar's icons.
GLYPHS = {
    "cont_backward": "◀◀",
    "step_backward": "◀|",
    "cont": "▶",
    "halt": "‖",
    "step": "|▶",
    "step_over": "↷",
    "start": "Launch ▾",
    "stop": "■",
}


class DebugBar(Horizontal):
    """The debug toolbar of the main instance."""

    DEFAULT_CSS = """
    DebugBar {
        height: 1;
        width: auto;
    }
    DebugBar > Button {
        min-width: 3;
        margin: 0 1 0 0;
    }
    DebugBar > Select {
        width: 30;
    }
    DebugBar > Label {
        padding: 0 1;
    }
    """

    def __init__(self, workspace, *, id: str | None = None) -> None:  # pylint: disable=redefined-builtin
        super().__init__(id=id)
        self.presenter = DebugBarPresenter(workspace)
        self.presenter.on_changed = lambda: gui_thread_schedule_async(self.update_state)
        self.buttons = {
            action.name: Button(GLYPHS[action.name], id=f"dbg-{action.name}", compact=True, tooltip=action.tooltip)
            for action in DEBUG_ACTIONS
        }
        self.selector: Select[int] = Select(
            [(text, i) for i, text in enumerate(self.presenter.choices())],
            value=0,
            allow_blank=False,
            compact=True,
            id="dbg-select",
        )
        self.state_label = Label("", id="dbg-state")

    def compose(self) -> ComposeResult:
        yield from self.buttons.values()
        yield self.selector
        yield self.state_label

    def on_mount(self) -> None:
        self.presenter.start()
        self.update_state()

    def on_unmount(self) -> None:
        self.presenter.stop_listening()

    def update_state(self) -> None:
        """Enable and show the buttons as the debugger allows, and show the debuggers and the state."""
        if not self.is_attached:
            return
        for name, (enabled, visible) in self.presenter.action_states().items():
            button = self.buttons[name]
            button.disabled = not enabled
            button.display = visible
        choices = self.presenter.choices()
        options = [(text, i) for i, text in enumerate(choices)]
        if [text for text, _ in self.selector._options] != choices:  # pylint: disable=protected-access
            self.selector.set_options(options)
        index = self.presenter.current_index()
        if self.selector.value != index:
            self.selector.value = index
        self.selector.disabled = len(choices) == 1
        self.state_label.update(Text(self.presenter.state_text()))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        name = (event.button.id or "").removeprefix("dbg-")
        if name not in self.buttons:
            return
        event.stop()
        if name == "start":
            self.open_launch_menu()
            return
        getattr(self.presenter, name)()

    def open_launch_menu(self) -> None:
        open_menu = getattr(self.app, "open_context_menu", None)
        if open_menu is not None:
            region = self.buttons["start"].region
            open_menu(self.presenter.launch_menu(), (region.x, region.y + 1))

    def on_select_changed(self, event: Select.Changed) -> None:
        event.stop()
        value: Any = event.value
        if isinstance(value, int) and value != self.presenter.current_index():
            self.presenter.select_index(value)


__all__ = ["DebugBar"]
