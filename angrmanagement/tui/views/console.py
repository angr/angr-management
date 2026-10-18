"""
The Python console of the terminal frontend.

It runs an in-process IPython kernel (what qtconsole wraps in the Qt frontend), shows what the kernel prints in a
``RichLog`` and reads code from an ``Input`` with history (Up and Down) and completion from the kernel (Tab). It opens
with the kernel's banner and numbers the cells ``In [n]:`` as qtconsole does. The namespace is the Qt console's: angr,
claripy, cle, workspace, instance, project, and func once a function is shown. Like the Qt console, a cell runs on the
UI thread.
"""

from __future__ import annotations

import atexit
import logging
from typing import TYPE_CHECKING, Any, ClassVar

from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Input, Label, RichLog

from angrmanagement.present.base import InstancePresenter
from angrmanagement.present.console import console_namespace, function_namespace

from .base import TuiView

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.data.instance import Instance

_l = logging.getLogger(__name__)


class ConsolePresenter(InstancePresenter):
    """The console's kernel and its namespace."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "bottom") -> None:
        super().__init__(workspace, "console", instance, default_docking_position)
        self.base_caption = "Console"
        self.kernel_manager: Any = None
        self.kernel_client: Any = None
        self.error: str | None = None
        self.history: list[str] = []

    def start(self) -> bool:
        """Start the kernel; False, with :attr:`error` set, if it cannot run here."""
        if self.kernel_manager is not None:
            return True
        try:
            from ipykernel.inprocess.manager import InProcessKernelManager  # pylint:disable=import-outside-toplevel
            from traitlets.config.configurable import MultipleInstanceError  # pylint:disable=import-outside-toplevel
        except ImportError as ex:
            self.error = f"The console needs ipykernel: {ex}"
            return False
        try:
            km = InProcessKernelManager()
            km.start_kernel(show_banner=False)
        except MultipleInstanceError:
            self.error = (
                "The console cannot start because an IPython interpreter is already loaded. "
                "You might be running angr management with IPython."
            )
            return False
        self.kernel_manager = km
        self.kernel_client = km.client()
        self.kernel_client.start_channels()
        self.push_namespace(console_namespace(self.workspace, self.instance))
        return True

    def push_namespace(self, namespace: dict[str, Any]) -> None:
        if self.kernel_manager is not None:
            self.kernel_manager.kernel.shell.push(namespace)

    def reload(self) -> None:
        self.push_namespace(console_namespace(self.workspace, self.instance))

    @property
    def banner(self) -> str:
        """The kernel's banner (the Python and IPython versions and a tip), as qtconsole prints it first."""
        if self.kernel_manager is None:
            return ""
        return str(self.kernel_manager.kernel.banner)

    @property
    def execution_count(self) -> int:
        """The number the next cell runs as, the ``n`` of qtconsole's ``In [n]:``."""
        if self.kernel_manager is None:
            return 1
        return int(self.kernel_manager.kernel.shell.execution_count)

    def execute(self, code: str) -> list[dict]:
        """Run ``code`` and return the kernel's iopub messages about it."""
        if self.kernel_client is None:
            return []
        if code.strip():
            self.history.append(code)
        self.kernel_client.execute(code)
        messages = []
        while self.kernel_client.iopub_channel.msg_ready():
            messages.append(self.kernel_client.get_iopub_msg(timeout=0))
        # the execute reply
        while self.kernel_client.shell_channel.msg_ready():
            self.kernel_client.get_shell_msg(timeout=0)
        return messages

    def complete(self, code: str) -> tuple[list[str], int, int]:
        """The kernel's completions of ``code`` at its end, and the span they replace."""
        if self.kernel_client is None:
            return [], len(code), len(code)
        self.kernel_client.complete(code, len(code))
        while True:
            reply = self.kernel_client.get_shell_msg(timeout=1)
            if reply["msg_type"] == "complete_reply":
                content = reply["content"]
                return list(content.get("matches", [])), content.get("cursor_start", 0), content.get("cursor_end", 0)

    def close(self) -> None:
        if self.kernel_client is not None:
            self.kernel_client.stop_channels()
        if self.kernel_manager is not None:
            iopub = self.kernel_manager.kernel.iopub_thread
            self.kernel_manager.shutdown_kernel()
            # the kernel registered the stop of its IOPub thread at exit; the thread is stopped now, and the hook would
            # keep it, and the app's output capture it took when it started, for the life of the process
            atexit.unregister(iopub.stop)
        self.kernel_client = None
        self.kernel_manager = None


def message_text(msg: dict) -> Text | None:
    """What the console shows for one iopub message, or None."""
    msg_type = msg.get("msg_type")
    content = msg.get("content", {})
    if msg_type == "stream":
        return Text(content.get("text", "").rstrip("\n"), style="red" if content.get("name") == "stderr" else "")
    if msg_type in ("execute_result", "display_data"):
        data = content.get("data", {})
        text = data.get("text/plain")
        if text is None:
            return None
        if msg_type == "execute_result":
            prefix = Text(f"Out[{content.get('execution_count', '')}]: ", style="red")
            return prefix + Text(text)
        return Text(text)
    if msg_type == "error":
        return Text.from_ansi("\n".join(content.get("traceback", [])))
    return None


class ConsoleInput(Input):
    """The console's input line: Up and Down walk the history, Tab completes."""

    BINDINGS: ClassVar = [
        Binding("up", "history(-1)", "Previous", show=False),
        Binding("down", "history(1)", "Next", show=False),
        Binding("tab", "complete", "Complete", show=False, priority=True),
    ]

    def __init__(self, presenter: ConsolePresenter, **kwargs) -> None:
        super().__init__(compact=True, **kwargs)
        self.presenter = presenter
        self._history_index: int | None = None

    def action_history(self, step: int) -> None:
        history = self.presenter.history
        if not history:
            return
        index = len(history) if self._history_index is None else self._history_index
        index = max(0, min(len(history), index + step))
        self._history_index = index
        self.value = history[index] if index < len(history) else ""
        self.cursor_position = len(self.value)

    def action_complete(self) -> None:
        matches, start, end = self.presenter.complete(self.value)
        if not matches:
            return
        if len(matches) == 1:
            self.value = self.value[:start] + matches[0] + self.value[end:]
            self.cursor_position = len(self.value)
            return
        common = matches[0]
        for match in matches[1:]:
            while not match.startswith(common):
                common = common[:-1]
        if len(common) > end - start:
            self.value = self.value[:start] + common + self.value[end:]
            self.cursor_position = len(self.value)
        view = next((node for node in self.ancestors if isinstance(node, ConsoleTuiView)), None)
        if view is not None:
            view.print_text("  ".join(matches[:60]))

    def reset_history(self) -> None:
        self._history_index = None


class ConsoleTuiView(TuiView):
    """The Python console."""

    PRESENTER_CLASS = ConsolePresenter
    DEFAULT_CSS = """
    ConsoleTuiView > RichLog {
        height: 1fr;
    }
    ConsoleTuiView > Horizontal {
        height: auto;
    }
    ConsoleTuiView > Horizontal > Input {
        width: 1fr;
    }
    """

    presenter: ConsolePresenter

    def __init__(self, workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.output = RichLog(wrap=True, markup=False, highlight=False, max_lines=10000)
        self.input = ConsoleInput(self.presenter)
        self.prompt = Label(id="prompt")

    def compose(self) -> ComposeResult:
        yield self.output
        with Horizontal():
            yield self.prompt
            yield self.input

    def on_mount(self) -> None:
        if not self.presenter.start():
            self.output.write(Text(self.presenter.error or "The console is not available.", style="red"))
            self.input.disabled = True
            return
        # the kernel's banner and a blank line, as qtconsole starts
        self.output.write(Text(self.presenter.banner.rstrip("\n") + "\n"))
        self._show_prompt()

    def prompt_text(self, count: int | None = None) -> Text:
        """qtconsole's input prompt, ``In [n]: `` with the number bold, in its green."""
        count = self.presenter.execution_count if count is None else count
        return Text.assemble(("In [", "green"), (str(count), "bold green"), ("]: ", "green"))

    def _show_prompt(self) -> None:
        self.prompt.update(self.prompt_text())

    def close_view(self) -> None:
        self.presenter.close()

    #
    # What the workspace uses
    #

    @property
    def ipython_widget_available(self) -> bool:
        return self.presenter.kernel_client is not None

    def print_text(self, msg) -> None:
        text = str(msg)
        if text == "\n":
            return
        self.output.write(Text(text.rstrip("\n")))

    def push_namespace(self, namespace: dict[str, Any]) -> None:
        self.presenter.push_namespace(namespace)

    def set_input_buffer(self, text: str) -> None:
        self.input.value = text

    def set_current_function(self, func) -> None:
        self.push_namespace(function_namespace(func))

    def focus_view(self) -> None:
        self.input.focus()

    #
    # Running code
    #

    def execute(self, code: str) -> None:
        self.output.write(self.prompt_text() + Text(code))
        for msg in self.presenter.execute(code):
            text = message_text(msg)
            if text is not None:
                self.output.write(text)
        self._show_prompt()
        # like the Qt console: a cell that ran may have changed what the disassembly shows
        view = self.workspace.view_manager.first_view_in_category("disassembly")
        if view is not None:
            refresh = getattr(view, "refresh_view", None) or view.refresh
            refresh()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input is self.input:
            event.stop()
            code = event.value
            self.input.value = ""
            self.input.reset_history()
            self.execute(code)

    def on_key(self, event: events.Key) -> None:
        if event.key == "ctrl+l":
            event.stop()
            self.output.clear()
