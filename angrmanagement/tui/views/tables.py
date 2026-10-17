"""The table views of the terminal frontend: each is a presenter's table, a filter box and a few controls."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.containers import Horizontal
from textual.widgets import Button, Checkbox, Input, Label, Select

from angrmanagement.present.bookmarks import BookmarksPresenter
from angrmanagement.present.breakpoints import BreakpointsPresenter
from angrmanagement.present.comments import CommentsPresenter
from angrmanagement.present.functions import FunctionsPresenter
from angrmanagement.present.jobs import JobsPresenter
from angrmanagement.present.log import LogPresenter
from angrmanagement.present.mcp_history import MCPHistoryPresenter
from angrmanagement.present.patches import PatchesPresenter
from angrmanagement.present.registers import RegistersPresenter
from angrmanagement.present.signatures import SignaturesPresenter
from angrmanagement.present.stack import StackPresenter
from angrmanagement.present.strings import StringsPresenter
from angrmanagement.present.symexec import StatesPresenter
from angrmanagement.present.traces import TracesPresenter
from angrmanagement.tui.screens.signature_matches import SignatureMatchesScreen
from angrmanagement.tui.widgets.table import FilterableTable

from .base import TuiView

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

_TOOLBAR_CSS = """
{name} > .toolbar {{
    height: auto;
    width: 100%;
}}
{name} > .toolbar > * {{
    margin: 0 1 0 0;
}}
{name} > .toolbar Button {{
    min-width: 6;
}}
{name} > .toolbar Checkbox {{
    border: none;
    height: 1;
    padding: 0;
}}
{name} > .toolbar Label {{
    padding: 0 1;
}}
"""


def toolbar_css(name: str) -> str:
    return _TOOLBAR_CSS.format(name=name)


class TableTuiView(TuiView):
    """A view whose content is the presenter's table, with or without a filter box."""

    FILTER_PLACEHOLDER = "Filter..."
    SHOW_FILTER = False

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.table = self.make_table()

    def make_table(self) -> FilterableTable:
        return FilterableTable(
            self.presenter.model,
            placeholder=self.FILTER_PLACEHOLDER,
            status=self.status_text,
            show_filter=self.SHOW_FILTER,
            on_submit=self.on_filter_submitted,
        )

    def status_text(self) -> str:  # pylint:disable=no-self-use
        return ""

    def on_filter_submitted(self, text: str) -> None:
        """Enter in the filter box."""

    def compose(self) -> ComposeResult:
        yield self.table

    @property
    def table_widget(self):
        return self.table.table

    def focus_view(self) -> None:
        self.table.table.focus()


class FunctionsTuiView(TableTuiView):
    """The functions of the project; type to filter, Enter opens one."""

    PRESENTER_CLASS = FunctionsPresenter
    FILTER_PLACEHOLDER = "Filter by name..."
    SHOW_FILTER = True
    DEFAULT_CSS = toolbar_css("FunctionsTuiView")

    presenter: FunctionsPresenter

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Checkbox("Show alignment functions", self.presenter.show_alignment_functions, id="show-alignment")
        yield from super().compose()

    def on_mount(self) -> None:
        self.presenter.reload()

    def status_text(self) -> str:
        return self.presenter.count_text()

    def on_filter_submitted(self, text: str) -> None:
        self.presenter.jump_to_result()
        self.table.set_filter("")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "show-alignment" and event.value != self.presenter.show_alignment_functions:
            self.presenter.toggle_show_alignment_functions()

    def reset_cache_and_refresh(self) -> None:
        self.presenter.reset_cache_and_refresh()


class StringsTuiView(TableTuiView):
    """The strings the CFG found, all or one function's, with a wildcard or regex filter; X shows cross-references."""

    PRESENTER_CLASS = StringsPresenter
    DEFAULT_CSS = (
        toolbar_css("StringsTuiView") + "StringsTuiView Select { width: 40; } StringsTuiView Input { width: 1fr; }"
    )

    presenter: StringsPresenter

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Label("Function:")
            yield Select([], prompt="All functions", allow_blank=True, id="function", compact=True)
            yield Label("Filter:")
            yield Input(placeholder="Wildcard filter", id="filter", compact=True)
            yield Checkbox(".*", False, id="regex", tooltip="Regular expression")
        yield from super().compose()

    def on_mount(self) -> None:
        self.reload()

    def reload(self) -> None:
        self.presenter.reload()
        kb = self.instance.kb
        if kb is None:
            return
        select = self.query_one("#function", Select)
        options = [(f"{f.name} ({f.addr:#x})", f.addr) for f in kb.functions.values()]
        select.set_options(options)

    def status_text(self) -> str:
        return f"{self.presenter.model.row_count} strings"

    def on_select_changed(self, event: Select.Changed) -> None:
        kb = self.instance.kb
        value = event.value
        func = kb.functions.get_by_addr(value) if (kb is not None and isinstance(value, int)) else None
        if func is not self.presenter.selected_function:
            self.presenter.select_function(func)

    def _apply_filter(self) -> None:
        pattern = self.query_one("#filter", Input).value
        regex = self.query_one("#regex", Checkbox).value
        self.presenter.set_filter(pattern, regex=regex)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self._apply_filter()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "regex":
            self._apply_filter()

    def on_key(self, event: events.Key) -> None:
        if event.key in ("x", "X") and self.table_widget.has_focus:
            event.stop()
            self.show_xrefs()

    def show_xrefs(self) -> None:
        rows = self.table_widget.selected_rows
        string = self.presenter.model.row(rows[0]) if rows else None
        show = getattr(self.app, "show_xrefs", None)
        if string is not None and show is not None:
            show(addr=string.addr, dst_addr=string.addr, xrefs_manager=self.instance.project.kb.xrefs)


class PatchesTuiView(TableTuiView):
    """Every patch; the context menu reverts the selected one."""

    PRESENTER_CLASS = PatchesPresenter

    def on_mount(self) -> None:
        self.presenter.reload()


class CommentsTuiView(TableTuiView):
    """Every comment in the project; type to filter."""

    PRESENTER_CLASS = CommentsPresenter
    FILTER_PLACEHOLDER = "Filter comments..."
    SHOW_FILTER = True

    presenter: CommentsPresenter

    def on_mount(self) -> None:
        self.presenter.reload()

    def status_text(self) -> str:
        return self.presenter.count_text()


class BookmarksTuiView(TableTuiView):
    """The bookmarked addresses."""

    PRESENTER_CLASS = BookmarksPresenter


class SignaturesTuiView(TableTuiView):
    """The loaded function signatures and how many functions each matched."""

    PRESENTER_CLASS = SignaturesPresenter
    DEFAULT_CSS = toolbar_css("SignaturesTuiView")

    presenter: SignaturesPresenter

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Button("Load Signature Files...", id="load", compact=True)
            yield Button("Try Applying All Signatures", id="try-all", compact=True)
            yield Button("Find Matches Via Bindiff", id="bindiff", compact=True)
        yield from super().compose()

    def on_mount(self) -> None:
        self.presenter.reload()

    def show_signature_matches(self, sig: Any, matches: dict[int, str]) -> None:
        """The Signature Matches screen; applying it tells the workspace, as the Qt dialog's Apply does."""

        def done(result: str | None) -> None:
            if result == "applied":
                self.workspace.on_flirt_signatures_applied()

        presenter = self.presenter
        self.app.push_screen(
            SignatureMatchesScreen(self.workspace, sig, matches, presenter.instance, presenter.signature_mgr), done
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions: dict[str | None, Any] = {
            "load": self.presenter.load_signatures,
            "try-all": self.presenter.try_all_signatures,
            "bindiff": self.presenter.find_matches_via_bindiff,
        }
        action = actions.get(event.button.id)
        if action is not None:
            event.stop()
            run_off_ui = getattr(self.app, "run_blocking_action", None)
            if run_off_ui is not None and event.button.id in ("load", "bindiff"):
                # these ask for files: run them where they may wait for the answer
                run_off_ui(action)
            else:
                action()


class TracesTuiView(TableTuiView):
    """The loaded traces."""

    PRESENTER_CLASS = TracesPresenter


class BreakpointsTuiView(TableTuiView):
    """The breakpoints; the context menu adds, edits and removes them."""

    PRESENTER_CLASS = BreakpointsPresenter


class RegistersTuiView(TableTuiView):
    """The registers of the debugger's current state."""

    PRESENTER_CLASS = RegistersPresenter


class StackTuiView(TableTuiView):
    """The stack of the debugger's current state."""

    PRESENTER_CLASS = StackPresenter


class LogTuiView(TableTuiView):
    """The log; Ctrl+C copies the selected message, the context menu copies more or clears it."""

    PRESENTER_CLASS = LogPresenter
    DEFAULT_CSS = toolbar_css("LogTuiView")

    presenter: LogPresenter

    def compose(self) -> ComposeResult:
        yield from super().compose()
        with Horizontal(classes="toolbar"):
            yield Button("Copy", id="copy", compact=True)
            yield Button("Copy all", id="copy-all", compact=True)
            yield Button("Clear", id="clear", compact=True)

    def on_mount(self) -> None:
        self.presenter.model.changed.connect(self._scroll_to_end)
        self._scroll_to_end()

    def on_unmount(self) -> None:
        self.presenter.model.changed.disconnect(self._scroll_to_end)

    def _scroll_to_end(self, *_args) -> None:
        table = self.table_widget
        if table.row_count:
            table.move_cursor(row=table.row_count - 1, animate=False)

    def on_key(self, event: events.Key) -> None:
        if event.key == "ctrl+c" and self.table_widget.has_focus:
            event.stop()
            self.presenter.copy_selected_messages(self.table_widget.selected_rows)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "copy":
            self.presenter.copy_selected_messages(self.table_widget.selected_rows)
        elif event.button.id == "copy-all":
            self.presenter.copy_all()
        elif event.button.id == "clear":
            self.presenter.clear_log()


class JobsTuiView(TableTuiView):
    """The jobs and their progress; Delete or the context menu cancels the selected one."""

    PRESENTER_CLASS = JobsPresenter
    DEFAULT_CSS = toolbar_css("JobsTuiView")

    presenter: JobsPresenter

    def compose(self) -> ComposeResult:
        yield from super().compose()
        with Horizontal(classes="toolbar"):
            yield Button("Cancel job", id="cancel", compact=True)

    def _selected_job(self):
        rows = self.table_widget.selected_rows
        return self.presenter.model.row(rows[0]) if rows else None

    def on_key(self, event: events.Key) -> None:
        if event.key == "delete" and self.table_widget.has_focus:
            event.stop()
            self.cancel_selected()

    def cancel_selected(self) -> None:
        job = self._selected_job()
        if job is not None:
            self.presenter.cancel(job)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            event.stop()
            self.cancel_selected()


class MCPHistoryTuiView(TableTuiView):
    """The MCP tool calls an agent made against this session."""

    PRESENTER_CLASS = MCPHistoryPresenter
    DEFAULT_CSS = toolbar_css("MCPHistoryTuiView")

    presenter: MCPHistoryPresenter

    def compose(self) -> ComposeResult:
        yield from super().compose()
        with Horizontal(classes="toolbar"):
            yield Label(Text(""), id="spacer")
            yield Button("Clear", id="clear", compact=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "clear":
            event.stop()
            self.presenter.clear()


class StatesTuiView(TableTuiView):
    """The instance's symbolic states; the context menu makes, duplicates, deletes and simulates them."""

    PRESENTER_CLASS = StatesPresenter

    presenter: StatesPresenter
