from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from angrmanagement.data.jobs import SearchJob
from angrmanagement.data.jobs.job import JobState
from angrmanagement.data.search import (
    NAMED_CONSTANTS,
    VALUE_FORMATS,
    Searcher,
    SearchError,
    SearchKind,
    SearchQuery,
    available_scopes,
)
from angrmanagement.ui.widgets.qsearch_table import QSearchTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.data.search import SearchResult, SearchScope
    from angrmanagement.ui.workspace import Workspace


class SearchView(InstanceView):
    """
    A dockable search view: a query bar on top, a lazily-rendered result table below. All searching
    runs as a cancellable job in the worker thread.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("search", workspace, default_docking_position, instance)

        self.base_caption = "Search"
        self.width_hint = 800
        self.height_hint = 400

        self._scopes: list[SearchScope] = []
        self._job: SearchJob | None = None

        self._init_widgets()
        self.reload()

        self.workspace.job_manager.job_exception.connect(self._on_job_exception)
        self.instance.project.am_subscribe(self._on_project_updated)

    def closeEvent(self, event) -> None:
        self.instance.project.am_unsubscribe(self._on_project_updated)
        with contextlib.suppress(RuntimeError):
            self.workspace.job_manager.job_exception.disconnect(self._on_job_exception)
        super().closeEvent(event)

    def on_focused(self) -> None:
        # keep the "Current function" scope in sync with the disassembly view
        self._reload_scopes()
        super().on_focused()

    def sizeHint(self) -> QSize:
        return QSize(900, 400)

    #
    # Public methods
    #

    def reload(self) -> None:
        self._reload_scopes()

    def focus_query_box(self) -> None:
        self._query_box.setFocus()
        self._query_box.selectAll()

    @property
    def results(self) -> list[SearchResult]:
        return self._table.model_.results

    def search(self) -> None:
        """
        Build a query from the current widget state and dispatch it as a job.
        """
        if self.instance.project.am_none:
            self._set_status("No project is loaded.")
            return
        try:
            query = self.build_query()
        except SearchError as ex:
            self._set_status(str(ex))
            return

        self._table.set_results([])
        self._set_status("Searching...")
        self._search_button.setEnabled(False)
        self._cancel_button.setEnabled(True)

        job = SearchJob(self.instance, query, on_finish=self._on_search_finished)
        self._job = job
        self.workspace.job_manager.add_job(job)

    def cancel_search(self) -> None:
        if self._job is not None and self._job.state in (JobState.PENDING, JobState.RUNNING):
            self.workspace.job_manager.cancel_job(self._job)
            self._set_status("Cancelling...")

    def build_query(self) -> SearchQuery:
        """
        Build and validate a query from the current widget state. Raises SearchError if the query
        cannot be compiled.
        """
        kind = self._kind_combo.currentData()
        scope_idx = self._scope_combo.currentIndex()
        scope = self._scopes[scope_idx] if 0 <= scope_idx < len(self._scopes) else self._scopes[0]
        query = SearchQuery(
            kind=kind,
            text=self._query_box.text(),
            scope=scope,
            case_sensitive=self._case_box.isChecked(),
            regex=self._regex_box.isChecked(),
            alignment=self._alignment_box.value(),
            value_format=self._format_combo.currentText(),
            big_endian={"Little endian": False, "Big endian": True}.get(self._endness_combo.currentText()),
            search_data=self._data_box.isChecked(),
            search_code=self._code_box.isChecked(),
            decompile_on_demand=self._decompile_box.isChecked(),
        )
        Searcher(self.instance.project.am_obj, kb=self.instance.kb).validate(query)
        return query

    def navigate_to_result(self, result: SearchResult | None, category: str = "disassembly") -> None:
        """
        Bring the given result into view. Defaults to the disassembly view.
        """
        if result is None:
            return
        if category == "pseudocode":
            func_addr = result.func_addr if result.func_addr is not None else result.addr
            try:
                func = self.instance.kb.functions.get_by_addr(func_addr)
            except KeyError:
                func = None
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

    #
    # Clipboard helpers
    #

    @staticmethod
    def copy_addresses(results: list[SearchResult]) -> None:
        QGuiApplication.clipboard().setText("\n".join(f"{r.addr:#x}" for r in results))

    @staticmethod
    def copy_matches(results: list[SearchResult]) -> None:
        QGuiApplication.clipboard().setText("\n".join(r.text for r in results))

    @staticmethod
    def copy_rows(results: list[SearchResult]) -> None:
        QGuiApplication.clipboard().setText(
            "\n".join(f"{r.addr:#x}\t{r.kind}\t{r.func_name}\t{r.text}\t{r.context}" for r in results)
        )

    #
    # Event handlers
    #

    def _on_search_finished(self, results) -> None:
        self._search_button.setEnabled(True)
        self._cancel_button.setEnabled(False)
        results = results or []
        self._table.set_results(list(results))
        self._job = None
        self._update_status()

    def _on_job_exception(self, job, ex: BaseException) -> None:
        if job is not self._job:
            return
        self._search_button.setEnabled(True)
        self._cancel_button.setEnabled(False)
        cancelled = job.state == JobState.CANCELLED
        self._job = None
        self._set_status("Search cancelled." if cancelled else f"Search failed: {ex}")

    def _on_project_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self._table.set_results([])
        self._set_status("")
        self._reload_scopes()

    def _on_kind_changed(self) -> None:
        kind = self._kind_combo.currentData()
        self._case_box.setVisible(kind in (SearchKind.STRING, SearchKind.DISASSEMBLY, SearchKind.DECOMPILATION))
        self._regex_box.setVisible(kind in (SearchKind.STRING, SearchKind.DISASSEMBLY, SearchKind.DECOMPILATION))
        value_kind = kind is SearchKind.IMMEDIATE
        self._format_label.setVisible(value_kind)
        self._format_combo.setVisible(value_kind)
        self._endness_combo.setVisible(value_kind)
        self._constants_button.setVisible(value_kind)
        self._data_box.setVisible(value_kind)
        self._code_box.setVisible(value_kind)
        alignment_kind = kind in (SearchKind.BYTES, SearchKind.IMMEDIATE)
        self._alignment_label.setVisible(alignment_kind)
        self._alignment_box.setVisible(alignment_kind)
        self._decompile_box.setVisible(kind is SearchKind.DECOMPILATION)
        self._query_box.setPlaceholderText(self._placeholder_for(kind))

    def _on_filter_changed(self, text: str) -> None:
        self._table.filter(text)
        self._update_status()

    def _on_constant_selected(self) -> None:
        value, value_format = self.sender().data()
        self._query_box.setText(str(value))
        self._format_combo.setCurrentText(value_format)

    #
    # Private methods
    #

    @staticmethod
    def _placeholder_for(kind: SearchKind) -> str:
        return {
            SearchKind.BYTES: "48 8b ?? 41    (?? and ? are wildcards)",
            SearchKind.STRING: "Text or regular expression",
            SearchKind.IMMEDIATE: "0x1234 or 4660",
            SearchKind.DISASSEMBLY: "Instruction text or regular expression",
            SearchKind.DECOMPILATION: "Pseudocode text or regular expression",
        }.get(kind, "")

    def _reload_scopes(self) -> None:
        project = None if self.instance.project.am_none else self.instance.project.am_obj
        current_func_addr = None
        disasm_view = self.workspace.view_manager.first_view_in_category("disassembly")
        if disasm_view is not None and disasm_view.function is not None and not disasm_view.function.am_none:
            current_func_addr = disasm_view.function.addr

        previous = self._scope_combo.currentText()
        self._scopes = available_scopes(project, current_func_addr)
        self._scope_combo.blockSignals(True)
        self._scope_combo.clear()
        self._scope_combo.addItems([s.name for s in self._scopes])
        idx = self._scope_combo.findText(previous)
        self._scope_combo.setCurrentIndex(max(idx, 0))
        self._scope_combo.blockSignals(False)

    def _set_status(self, text: str) -> None:
        self._status_label.setText(text)

    def _update_status(self) -> None:
        shown = len(self._table.model_.results)
        total = self._table.model_.total_count
        if shown == total:
            self._set_status(f"{total} results")
        else:
            self._set_status(f"{shown}/{total} results")

    def _init_widgets(self) -> None:
        self._kind_combo = QComboBox(self)
        for kind in SearchKind:
            self._kind_combo.addItem(kind.value, kind)
        self._kind_combo.currentIndexChanged.connect(self._on_kind_changed)

        self._query_box = QLineEdit(self)
        self._query_box.returnPressed.connect(self.search)

        self._scope_combo = QComboBox(self)
        self._scope_combo.setMinimumWidth(160)

        self._case_box = QCheckBox("Case", self)
        self._case_box.setToolTip("Case sensitive")
        self._regex_box = QCheckBox("Regex", self)
        self._regex_box.setToolTip("Interpret the query as a regular expression")

        self._format_label = QLabel("Type:", self)
        self._format_combo = QComboBox(self)
        self._format_combo.addItems(list(VALUE_FORMATS))
        self._format_combo.setCurrentText("int32")
        self._endness_combo = QComboBox(self)
        self._endness_combo.addItems(["Arch endian", "Little endian", "Big endian"])

        self._constants_button = QPushButton("Constants", self)
        constants_menu = QMenu(self)
        for name, (value, value_format) in NAMED_CONSTANTS.items():
            act = QAction(f"{name}: {value}", constants_menu)
            act.setData((value, value_format))
            act.triggered.connect(self._on_constant_selected)
            constants_menu.addAction(act)
        self._constants_button.setMenu(constants_menu)

        self._data_box = QCheckBox("Data", self)
        self._data_box.setToolTip("Match the encoded value anywhere in memory")
        self._data_box.setChecked(True)
        self._code_box = QCheckBox("Operands", self)
        self._code_box.setToolTip("Match instruction operands")
        self._code_box.setChecked(True)

        self._alignment_label = QLabel("Align:", self)
        self._alignment_box = QSpinBox(self)
        self._alignment_box.setRange(1, 256)
        self._alignment_box.setValue(1)

        self._decompile_box = QCheckBox("Decompile on demand", self)
        self._decompile_box.setToolTip(
            "Decompile functions that have not been decompiled yet. This can be very slow on large binaries."
        )

        self._search_button = QPushButton("Search", self)
        self._search_button.clicked.connect(self.search)
        self._cancel_button = QPushButton("Cancel", self)
        self._cancel_button.clicked.connect(self.cancel_search)
        self._cancel_button.setEnabled(False)

        query_layout = QHBoxLayout()
        query_layout.addWidget(QLabel("Search:", self))
        query_layout.addWidget(self._kind_combo)
        query_layout.addWidget(self._query_box, 1)
        query_layout.addWidget(QLabel("In:", self))
        query_layout.addWidget(self._scope_combo)
        query_layout.addWidget(self._search_button)
        query_layout.addWidget(self._cancel_button)
        query_layout.setContentsMargins(3, 3, 3, 3)
        query_layout.setSpacing(3)

        options_layout = QHBoxLayout()
        options_layout.addWidget(self._case_box)
        options_layout.addWidget(self._regex_box)
        options_layout.addWidget(self._format_label)
        options_layout.addWidget(self._format_combo)
        options_layout.addWidget(self._endness_combo)
        options_layout.addWidget(self._constants_button)
        options_layout.addWidget(self._data_box)
        options_layout.addWidget(self._code_box)
        options_layout.addWidget(self._alignment_label)
        options_layout.addWidget(self._alignment_box)
        options_layout.addWidget(self._decompile_box)
        options_layout.addStretch(1)
        options_layout.setContentsMargins(3, 0, 3, 3)
        options_layout.setSpacing(3)

        self._table = QSearchTable(self, self)

        self._filter_box = QLineEdit(self)
        self._filter_box.setPlaceholderText("Filter results...")
        self._filter_box.setClearButtonEnabled(True)
        self._filter_box.textChanged.connect(self._on_filter_changed)
        self._status_label = QLabel("", self)

        status_layout = QHBoxLayout()
        status_layout.addWidget(self._filter_box, 1)
        status_layout.addWidget(self._status_label)
        status_layout.setContentsMargins(3, 3, 3, 3)
        status_layout.setSpacing(3)

        layout = QVBoxLayout()
        layout.addLayout(query_layout)
        layout.addLayout(options_layout)
        layout.addWidget(self._table, 1)
        layout.addLayout(status_layout)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        self.setFocusProxy(self._query_box)
        self._on_kind_changed()

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.cancel_search()
            return
        super().keyPressEvent(event)
