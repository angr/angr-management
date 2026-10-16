"""The search view of the terminal frontend: a query form over the search presenter, and the result table."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.containers import Horizontal
from textual.widgets import Button, Checkbox, Input, Label, Select

from angrmanagement.data.search import NAMED_CONSTANTS, VALUE_FORMATS, SearchError, SearchKind
from angrmanagement.present.menus import Menu, MenuEntry
from angrmanagement.present.search import ALIGNED_KINDS, ENDNESS_CHOICES, TEXT_KINDS, SearchPresenter, placeholder_for
from angrmanagement.tui.widgets.table import FilterableTable

from .base import TuiView
from .tables import toolbar_css

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

    from angrmanagement.data.search import SearchResult


class SearchTuiView(TuiView):
    """Search the binary for bytes, strings, values, instructions or pseudocode; Escape cancels a running search."""

    PRESENTER_CLASS = SearchPresenter
    DEFAULT_CSS = (
        toolbar_css("SearchTuiView")
        + """
    SearchTuiView #query { width: 1fr; }
    SearchTuiView #kind { width: 20; }
    SearchTuiView #scope { width: 30; }
    SearchTuiView #format { width: 14; }
    SearchTuiView #endness { width: 18; }
    SearchTuiView #alignment { width: 8; }
    """
    )

    presenter: SearchPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.results = FilterableTable(
            self.presenter.results_model,
            placeholder="Filter results...",
            on_filter=self.presenter.filter_results,
            status=lambda: self.presenter.status,
        )

    def compose(self) -> ComposeResult:
        kinds = [(kind.value, kind) for kind in SearchKind]
        with Horizontal(classes="toolbar"):
            yield Label("Search:")
            yield Select(kinds, value=SearchKind(kinds[0][1]), allow_blank=False, id="kind", compact=True)
            yield Input(placeholder="", id="query", compact=True)
            yield Label("In:")
            scopes = [(s.name, s.name) for s in self.presenter.scopes] or [
                ("Entire address space", "Entire address space")
            ]
            yield Select(scopes, value=scopes[0][1], allow_blank=False, id="scope", compact=True)
            yield Button("Search", id="search", variant="primary", compact=True)
            yield Button("Cancel", id="cancel", disabled=True, compact=True)
        with Horizontal(classes="toolbar", id="options"):
            yield Checkbox("Aa", False, id="case", tooltip="Case sensitive")
            yield Checkbox(".*", False, id="regex", tooltip="Regular expression")
            yield Label("Type:", id="format-label")
            yield Select([(f, f) for f in VALUE_FORMATS], value="int32", allow_blank=False, id="format", compact=True)
            yield Select(
                [(e, e) for e in ENDNESS_CHOICES],
                value=ENDNESS_CHOICES[0],
                allow_blank=False,
                id="endness",
                compact=True,
            )
            yield Button("Constants", id="constants", compact=True)
            yield Checkbox("Data", True, id="data", tooltip="Match the encoded value anywhere in memory")
            yield Checkbox("Operands", True, id="code", tooltip="Match instruction operands")
            yield Label("Align:", id="alignment-label")
            yield Input("1", id="alignment", restrict=r"[0-9]*", compact=True)
            yield Checkbox("Decompile on demand", False, id="decompile")
            yield Label("", id="decomp-count")
        yield self.results

    def on_mount(self) -> None:
        self.presenter.status_changed.connect(self._on_status_changed)
        self.presenter.busy_changed.connect(self._on_busy_changed)
        self.presenter.scopes_changed.connect(self._on_scopes_changed)
        self._on_scopes_changed()
        self._on_kind_changed()

    def on_unmount(self) -> None:
        self.presenter.status_changed.disconnect(self._on_status_changed)
        self.presenter.busy_changed.disconnect(self._on_busy_changed)
        self.presenter.scopes_changed.disconnect(self._on_scopes_changed)

    def reload(self) -> None:
        self.presenter.reload()

    def focus_query_box(self) -> None:
        if not self.is_mounted:
            self.app.call_after_refresh(self.focus_query_box)
            return
        self.query_one("#query", Input).focus()

    def focus_view(self) -> None:
        self.focus_query_box()

    @property
    def kind(self) -> SearchKind:
        value = self.query_one("#kind", Select).value
        return value if isinstance(value, SearchKind) else SearchKind.BYTES

    @property
    def results_list(self) -> list[SearchResult]:
        return self.presenter.results

    #
    # Searching
    #

    def search(self) -> None:
        if self.instance.project.am_none:
            self.presenter.set_status("No project is loaded.")
            return
        scope = self.query_one("#scope", Select)
        scope_index = next((i for i, s in enumerate(self.presenter.scopes) if s.name == scope.value), 0)
        alignment = self.query_one("#alignment", Input).value
        try:
            query = self.presenter.build_query(
                kind=self.kind,
                text=self.query_one("#query", Input).value,
                scope_index=scope_index,
                case_sensitive=self.query_one("#case", Checkbox).value,
                regex=self.query_one("#regex", Checkbox).value,
                alignment=int(alignment) if alignment else 1,
                value_format=str(self.query_one("#format", Select).value),
                endness=str(self.query_one("#endness", Select).value),
                search_data=self.query_one("#data", Checkbox).value,
                search_code=self.query_one("#code", Checkbox).value,
                decompile_on_demand=self.query_one("#decompile", Checkbox).value,
            )
        except SearchError as ex:
            self.presenter.set_status(str(ex))
            return
        self.presenter.start_search(query)

    #
    # Events
    #

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "search":
            self.search()
        elif event.button.id == "cancel":
            self.presenter.cancel_search()
        elif event.button.id == "constants":
            self._show_constants(event.button)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "query":
            event.stop()
            self.search()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "kind":
            self._on_kind_changed()

    def on_key(self, event: events.Key) -> None:
        if event.key == "escape" and self.presenter.searching:
            event.stop()
            self.presenter.cancel_search()

    def _show_constants(self, button: Button) -> None:
        menu = Menu("Constants")
        for name, (value, value_format) in NAMED_CONSTANTS.items():
            menu.add(MenuEntry(f"{name}: {value}", lambda v=value, f=value_format: self._use_constant(v, f)))
        open_menu = getattr(self.app, "open_context_menu", None)
        if open_menu is not None:
            open_menu(menu, (button.region.x, button.region.bottom))

    def _use_constant(self, value, value_format: str) -> None:
        self.query_one("#query", Input).value = str(value)
        self.query_one("#format", Select).value = value_format

    def _on_kind_changed(self) -> None:
        kind = self.kind
        text_kind = kind in TEXT_KINDS
        for widget_id in ("#case", "#regex"):
            self.query_one(widget_id).display = text_kind
        value_kind = kind is SearchKind.IMMEDIATE
        for widget_id in ("#format-label", "#format", "#endness", "#constants", "#data", "#code"):
            self.query_one(widget_id).display = value_kind
        aligned = kind in ALIGNED_KINDS
        for widget_id in ("#alignment-label", "#alignment"):
            self.query_one(widget_id).display = aligned
        decompilation = kind is SearchKind.DECOMPILATION
        self.query_one("#decompile").display = decompilation
        count = self.query_one("#decomp-count", Label)
        count.display = decompilation
        if decompilation:
            count.update(Text(self.presenter.decompiled_count_text()))
        self.query_one("#query", Input).placeholder = placeholder_for(kind)

    def _on_status_changed(self, _text: str) -> None:
        self.results.refresh_status()

    def _on_busy_changed(self, searching: bool) -> None:
        self.query_one("#search", Button).disabled = searching
        self.query_one("#cancel", Button).disabled = not searching
        if not searching and self.kind is SearchKind.DECOMPILATION:
            self.query_one("#decomp-count", Label).update(Text(self.presenter.decompiled_count_text()))

    def _on_scopes_changed(self) -> None:
        if not self.is_mounted:
            return
        scope = self.query_one("#scope", Select)
        previous = scope.value
        names = [s.name for s in self.presenter.scopes]
        if not names:
            return
        scope.set_options([(name, name) for name in names])
        if previous in names:
            scope.value = previous
        elif names:
            scope.value = names[0]
