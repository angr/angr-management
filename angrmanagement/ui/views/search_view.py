from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction
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

from angrmanagement.data.search import (
    NAMED_CONSTANTS,
    VALUE_FORMATS,
    SearchError,
    SearchKind,
    SearchQuery,
)
from angrmanagement.present import search as search_presenter
from angrmanagement.present.search import ALIGNED_KINDS, ENDNESS_CHOICES, TEXT_KINDS, SearchPresenter
from angrmanagement.ui.widgets.qsearch_table import QSearchTable

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.data.search import SearchResult
    from angrmanagement.ui.workspace import Workspace


class SearchView(InstanceView):
    """
    A dockable search view: a query bar on top, a lazily-rendered result table below. All searching
    runs as a cancellable job in the worker thread.
    """

    presenter: SearchPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "search",
            workspace,
            default_docking_position,
            instance,
            SearchPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "Search"
        self.width_hint = 800
        self.height_hint = 400

        self._init_widgets()
        self.presenter.status_changed.connect(self._set_status)
        self.presenter.busy_changed.connect(self._on_busy_changed)
        self.presenter.scopes_changed.connect(self._on_scopes_changed)
        self.instance.project.am_subscribe(self._on_project_updated)
        self.reload()

    def closeEvent(self, event) -> None:
        self.instance.project.am_unsubscribe(self._on_project_updated)
        self.presenter.status_changed.disconnect(self._set_status)
        self.presenter.busy_changed.disconnect(self._on_busy_changed)
        self.presenter.scopes_changed.disconnect(self._on_scopes_changed)
        self.presenter.close()
        super().closeEvent(event)

    def on_focused(self) -> None:
        # keep the "Current function" scope in sync with the disassembly view
        self._reload_scopes()
        self._update_decomp_count()
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
        self.presenter.start_search(query)

    def cancel_search(self) -> None:
        self.presenter.cancel_search()

    def build_query(self) -> SearchQuery:
        """
        Build and validate a query from the current widget state. Raises SearchError if the query cannot be compiled.
        """
        return self.presenter.build_query(
            kind=self._kind_combo.currentData(),
            text=self._query_box.text(),
            scope_index=self._scope_combo.currentIndex(),
            case_sensitive=self._case_box.isChecked(),
            regex=self._regex_box.isChecked(),
            alignment=self._alignment_box.value(),
            value_format=self._format_combo.currentText(),
            endness=self._endness_combo.currentText(),
            search_data=self._data_box.isChecked(),
            search_code=self._code_box.isChecked(),
            decompile_on_demand=self._decompile_box.isChecked(),
        )

    def navigate_to_result(self, result: SearchResult | None, category: str = "disassembly") -> None:
        """
        Bring the given result into view. Defaults to the disassembly view.
        """
        self.presenter.navigate_to_result(result, category)

    #
    # Clipboard helpers
    #

    @staticmethod
    def copy_addresses(results: list[SearchResult]) -> None:
        search_presenter.copy_addresses(results)

    @staticmethod
    def copy_matches(results: list[SearchResult]) -> None:
        search_presenter.copy_matches(results)

    @staticmethod
    def copy_rows(results: list[SearchResult]) -> None:
        search_presenter.copy_rows(results)

    #
    # Event handlers
    #

    def _on_busy_changed(self, searching: bool) -> None:
        self._search_button.setEnabled(not searching)
        self._cancel_button.setEnabled(searching)
        self._table.viewport_update()
        if not searching:
            # decompile-on-demand searches grow the decompilation cache
            self._update_decomp_count()

    def _on_scopes_changed(self) -> None:
        previous = self._scope_combo.currentText()
        self._scope_combo.blockSignals(True)
        self._scope_combo.clear()
        self._scope_combo.addItems([s.name for s in self.presenter.scopes])
        idx = self._scope_combo.findText(previous)
        self._scope_combo.setCurrentIndex(max(idx, 0))
        self._scope_combo.blockSignals(False)

    def _on_project_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self._table.viewport_update()
        self._update_decomp_count()

    def _on_kind_changed(self) -> None:
        kind = self._kind_combo.currentData()
        self._case_box.setVisible(kind in TEXT_KINDS)
        self._regex_box.setVisible(kind in TEXT_KINDS)
        value_kind = kind is SearchKind.IMMEDIATE
        self._format_label.setVisible(value_kind)
        self._format_combo.setVisible(value_kind)
        self._endness_combo.setVisible(value_kind)
        self._constants_button.setVisible(value_kind)
        self._data_box.setVisible(value_kind)
        self._code_box.setVisible(value_kind)
        alignment_kind = kind in ALIGNED_KINDS
        self._alignment_label.setVisible(alignment_kind)
        self._alignment_box.setVisible(alignment_kind)
        decompilation_kind = kind is SearchKind.DECOMPILATION
        self._decompile_box.setVisible(decompilation_kind)
        self._decomp_count_label.setVisible(decompilation_kind)
        if decompilation_kind:
            self._update_decomp_count()
        self._query_box.setPlaceholderText(self._placeholder_for(kind))

    def _on_filter_changed(self, text: str) -> None:
        self.presenter.filter_results(text)
        self._table.viewport_update()

    def _on_constant_selected(self) -> None:
        value, value_format = self.sender().data()
        self._query_box.setText(str(value))
        self._format_combo.setCurrentText(value_format)

    #
    # Private methods
    #

    @staticmethod
    def _placeholder_for(kind: SearchKind) -> str:
        return search_presenter.placeholder_for(kind)

    @property
    def _scopes(self):
        return self.presenter.scopes

    def _reload_scopes(self) -> None:
        self.presenter.reload_scopes()

    def _update_decomp_count(self) -> None:
        self._decomp_count_label.setText(self.presenter.decompiled_count_text())

    def _set_status(self, text: str) -> None:
        self._status_label.setText(text)

    def _update_status(self) -> None:
        self.presenter.update_status()

    def _init_widgets(self) -> None:
        self._kind_combo = QComboBox(self)
        for kind in SearchKind:
            self._kind_combo.addItem(kind.value, kind)
        self._kind_combo.currentIndexChanged.connect(self._on_kind_changed)

        self._query_box = QLineEdit(self)
        self._query_box.returnPressed.connect(self.search)

        self._scope_combo = QComboBox(self)
        self._scope_combo.setMinimumWidth(160)

        self._case_box = QCheckBox("Aa", self)
        self._case_box.setToolTip("Case sensitive")
        self._regex_box = QCheckBox(".*", self)
        self._regex_box.setToolTip("Regular expression")

        self._format_label = QLabel("Type:", self)
        self._format_combo = QComboBox(self)
        self._format_combo.addItems(list(VALUE_FORMATS))
        self._format_combo.setCurrentText("int32")
        self._endness_combo = QComboBox(self)
        self._endness_combo.addItems(list(ENDNESS_CHOICES))

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
        self._decomp_count_label = QLabel("", self)
        self._decomp_count_label.setToolTip(
            'Functions with a cached decompilation. Without "Decompile on demand", only these are searched.'
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
        options_layout.addWidget(self._decomp_count_label)
        options_layout.addStretch(1)
        options_layout.setContentsMargins(3, 0, 3, 3)
        options_layout.setSpacing(3)

        self._table = QSearchTable(self, self, self.presenter.results_model)

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
