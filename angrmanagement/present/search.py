"""The search view without a toolkit: its result table, the query it runs and where a result leads."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, ClassVar

from angrmanagement.data.jobs import SearchJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.data.search import Searcher, SearchError, SearchKind, SearchQuery, available_scopes
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.signal import Signal

from .base import InstancePresenter, project_of
from .keymap import search_keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.search import SearchResult, SearchScope

    from .keymap import Keymap

#: The kinds whose matches can be case sensitive or regular expressions.
TEXT_KINDS = (SearchKind.STRING, SearchKind.DISASSEMBLY, SearchKind.DECOMPILATION)
#: The kinds that search for a value or a byte pattern at some alignment.
ALIGNED_KINDS = (SearchKind.BYTES, SearchKind.IMMEDIATE)
ENDNESS_CHOICES = ("Arch endian", "Little endian", "Big endian")


def placeholder_for(kind: SearchKind) -> str:
    """The hint shown in an empty query box for ``kind``."""
    return {
        SearchKind.BYTES: "48 8b ?? 41    (?? and ? are wildcards)",
        SearchKind.STRING: "Text or regular expression",
        SearchKind.IMMEDIATE: "0x1234 or 4660",
        SearchKind.DISASSEMBLY: "Instruction text or regular expression",
        SearchKind.DECOMPILATION: "Pseudocode text or regular expression",
    }.get(kind, "")


def addresses_text(results: Sequence[SearchResult]) -> str:
    return "\n".join(f"{r.addr:#x}" for r in results)


def matches_text(results: Sequence[SearchResult]) -> str:
    return "\n".join(r.text for r in results)


def rows_text(results: Sequence[SearchResult]) -> str:
    return "\n".join(f"{r.addr:#x}\t{r.kind}\t{r.func_name}\t{r.text}\t{r.context}" for r in results)


def copy_addresses(results: Sequence[SearchResult]) -> None:
    GlobalInfo.ui_services.set_clipboard_text(addresses_text(results))


def copy_matches(results: Sequence[SearchResult]) -> None:
    GlobalInfo.ui_services.set_clipboard_text(matches_text(results))


def copy_rows(results: Sequence[SearchResult]) -> None:
    GlobalInfo.ui_services.set_clipboard_text(rows_text(results))


class SearchResultsModel(ListTableModel["SearchResult"]):
    """
    Table over a list of :class:`SearchResult`. Rows are plain dataclasses and the frontends draw only what is
    visible, so a result set of tens of thousands of hits costs nothing to display.
    """

    ADDRESS_COL = 0
    KIND_COL = 1
    FUNCTION_COL = 2
    MATCH_COL = 3
    CONTEXT_COL = 4

    COLUMNS: ClassVar[list[Column]] = [
        Column("Address", 15),
        Column("Kind", 14),
        Column("Function", 20),
        Column("Match", 32),
        Column("Context", stretch=True),
    ]
    HEADER: ClassVar[list[str]] = [c.name for c in COLUMNS]

    def __init__(self, presenter: SearchPresenter | None = None) -> None:
        super().__init__()
        self.presenter = presenter

    @property
    def results(self) -> list[SearchResult]:
        return self.rows

    def set_results(self, results: Sequence[SearchResult]) -> None:
        self.set_rows(results)

    def result_at(self, row: int) -> SearchResult | None:
        return self.row(row)

    def column_text(self, obj: SearchResult, col: int) -> str:
        return self.result_column_text(obj, col)

    def column_value(self, obj: SearchResult, col: int) -> Any:
        if col == self.ADDRESS_COL:
            return obj.addr
        return self.result_column_text(obj, col)

    @classmethod
    def result_column_text(cls, result: SearchResult, col: int) -> str:
        if col == cls.ADDRESS_COL:
            return f"{result.addr:#x}"
        if col == cls.KIND_COL:
            return result.kind
        if col == cls.FUNCTION_COL:
            return result.func_name or (f"{result.func_addr:#x}" if result.func_addr is not None else "")
        if col == cls.MATCH_COL:
            return result.text
        if col == cls.CONTEXT_COL:
            return result.context
        return ""

    def on_activate(self, obj: SearchResult) -> None:
        if self.presenter is not None:
            self.presenter.navigate_to_result(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        if self.presenter is None:
            return None
        return self.presenter.results_menu(self.objects(rows))


class SearchPresenter(InstancePresenter):
    """
    The search view: builds a query, runs it as a cancellable job, and lists the results.

    ``status_changed(text)`` reports progress and errors; ``busy_changed(searching)`` says whether a search is running;
    ``scopes_changed()`` says the list of scopes was rebuilt.
    """

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "search", instance, default_docking_position)
        self.base_caption = "Search"
        self.results_model = SearchResultsModel(self)
        self.scopes: list[SearchScope] = []
        self.status: str = ""
        self._job: SearchJob | None = None
        self.status_changed = Signal(str, name="SearchPresenter.status_changed")
        self.busy_changed = Signal(bool, name="SearchPresenter.busy_changed")
        self.scopes_changed = Signal(name="SearchPresenter.scopes_changed")

        self.workspace.job_manager.job_exception.connect(self._on_job_exception)
        self.instance.project.am_subscribe(self._on_project_updated)
        self.reload_scopes()

    def close(self) -> None:
        self.instance.project.am_unsubscribe(self._on_project_updated)
        with contextlib.suppress(RuntimeError):
            self.workspace.job_manager.job_exception.disconnect(self._on_job_exception)

    @property
    def keymap(self) -> Keymap:
        return search_keymap()

    @property
    def searching(self) -> bool:
        return self._job is not None

    #
    # Scopes and counts
    #

    def reload(self) -> None:
        self.reload_scopes()

    def on_focused(self) -> None:
        # keep the "Current function" scope in sync with the disassembly view
        self.reload_scopes()
        super().on_focused()

    def current_function_addr(self) -> int | None:
        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        function = getattr(disasm_view, "function", None)
        if function is not None and not function.am_none:
            return function.addr
        return None

    def reload_scopes(self) -> list[SearchScope]:
        self.scopes = available_scopes(project_of(self.instance), self.current_function_addr())
        self.scopes_changed.emit()
        return self.scopes

    def scope_at(self, index: int) -> SearchScope:
        return self.scopes[index] if 0 <= index < len(self.scopes) else self.scopes[0]

    def decompiled_function_count(self) -> int:
        if self.instance.project.am_none:
            return 0
        decompilations = getattr(self.instance.kb, "decompilations", None)
        if decompilations is None:
            return 0
        return len({key[0] for key in decompilations.cached if isinstance(key, tuple) and len(key) == 2})

    def decompiled_count_text(self) -> str:
        count = self.decompiled_function_count()
        plural = "" if count == 1 else "s"
        return f"{count} function{plural} decompiled"

    #
    # Searching
    #

    def build_query(
        self,
        kind: SearchKind,
        text: str,
        scope_index: int = 0,
        case_sensitive: bool = False,
        regex: bool = False,
        alignment: int = 1,
        value_format: str = "int32",
        endness: str = "Arch endian",
        search_data: bool = True,
        search_code: bool = True,
        decompile_on_demand: bool = False,
    ) -> SearchQuery:
        """
        Build and validate a query. Raises SearchError if it cannot be compiled.
        """
        query = SearchQuery(
            kind=kind,
            text=text,
            scope=self.scope_at(scope_index),
            case_sensitive=case_sensitive,
            regex=regex,
            alignment=alignment,
            value_format=value_format,
            big_endian={"Little endian": False, "Big endian": True}.get(endness),
            search_data=search_data,
            search_code=search_code,
            decompile_on_demand=decompile_on_demand,
        )
        project = project_of(self.instance)
        if project is None:
            raise SearchError("No project is loaded.")
        Searcher(project, kb=self.instance.kb).validate(query)
        return query

    def start_search(self, query: SearchQuery) -> None:
        """Dispatch ``query`` as a job; the results replace the table when it finishes."""
        if self.instance.project.am_none:
            self.set_status("No project is loaded.")
            return
        self.results_model.set_results([])
        self.set_status("Searching...")
        job = SearchJob(self.instance, query, on_finish=self._on_search_finished)
        self._job = job
        self.busy_changed.emit(True)
        self.workspace.job_manager.add_job(job)

    def cancel_search(self) -> None:
        if self._job is not None and self._job.state in (JobState.PENDING, JobState.RUNNING):
            self.workspace.job_manager.cancel_job(self._job)
            self.set_status("Cancelling...")

    def filter_results(self, text: str) -> None:
        self.results_model.filter(text)
        self.update_status()

    def set_status(self, text: str) -> None:
        self.status = text
        self.status_changed.emit(text)

    def update_status(self) -> None:
        shown = self.results_model.row_count
        total = self.results_model.total_count
        self.set_status(f"{total} results" if shown == total else f"{shown}/{total} results")

    #
    # Results
    #

    @property
    def results(self) -> list[SearchResult]:
        return self.results_model.results

    def navigate_to_result(self, result: SearchResult | None, category: str = "disassembly") -> None:
        """
        Bring the given result into view. Defaults to the disassembly view.
        """
        if result is None:
            return
        if category == "pseudocode":
            func_addr = result.func_addr if result.func_addr is not None else result.addr
            kb = self.instance.kb
            func = None
            if kb is not None:
                with contextlib.suppress(KeyError):
                    func = kb.functions.get_by_addr(func_addr)
            if func is not None:
                self.workspace.decompile_function(func, curr_ins=result.addr)
                return
        elif category == "hex":
            view = self.workspace.view_manager.first_view_in_category("hex")
            if view is not None:
                view.jump_to(result.addr)
                self.workspace.view_manager.raise_view(view)
                return
        self.workspace.jump_to(result.addr)

    def results_menu(self, results: Sequence[SearchResult]) -> Menu | None:
        """The context menu of the selected results."""
        if not results:
            return None
        results = list(results)
        menu = Menu("")
        menu.add(MenuEntry("Copy &address", lambda: copy_addresses(results)))
        menu.add(MenuEntry("Copy &match", lambda: copy_matches(results)))
        menu.add(MenuEntry("Copy &row", lambda: copy_rows(results)))
        menu.add(MenuSeparator())
        for caption, category in (
            ("Jump in &disassembly", "disassembly"),
            ("Jump in &pseudocode", "pseudocode"),
            ("Jump in &hex view", "hex"),
        ):
            menu.add(MenuEntry(caption, lambda c=category: self.navigate_to_result(results[0], category=c)))
        return menu

    #
    # Events
    #

    def _on_search_finished(self, results) -> None:
        self._job = None
        self.busy_changed.emit(False)
        self.results_model.set_results(list(results or []))
        self.update_status()

    def _on_job_exception(self, job, ex: BaseException) -> None:
        if job is not self._job:
            return
        cancelled = job.state == JobState.CANCELLED
        self._job = None
        self.busy_changed.emit(False)
        self.set_status("Search cancelled." if cancelled else f"Search failed: {ex}")

    def _on_project_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.results_model.set_results([])
        self.set_status("")
        self.reload_scopes()
