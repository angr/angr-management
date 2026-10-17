from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDoubleSpinBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.present.graphs import convert_graph
from angrmanagement.present.patterns import (
    DEFAULT_MIN_IDENTITY,
    DEFAULT_MIN_SIZE,
    DEFAULT_STATEMENTS,
    STATEMENT_MODES,
    PatternViewMixin,
    family_cells,
    found_cell,
    match_cells,
    pattern_tree,
)
from angrmanagement.ui.menus.menu import to_qmenu
from angrmanagement.ui.views.view import InstanceView
from angrmanagement.ui.widgets.qpattern_graph import QPatternGraph, QPatternNode
from angrmanagement.ui.widgets.qpattern_library import QPatternLibrary
from angrmanagement.ui.widgets.qproperty_editor import (
    BoolPropertyItem,
    ComboPropertyItem,
    FloatPropertyItem,
    GroupPropertyItem,
    IntPropertyItem,
    PropertyModel,
    QPropertyEditor,
    TextPropertyItem,
)

if TYPE_CHECKING:
    from angr.analyses.decompiler.known_patterns.edit import NodePath
    from angr.knowledge_plugins.patterns import StoredPattern

    from angrmanagement.data.instance import Instance
    from angrmanagement.present.patterns import PatternNodeRef, PropertyGroup, PropertySpec
    from angrmanagement.ui.workspace import Workspace

#: the property sheet's item class of each kind of property
_PROPERTY_ITEMS = {
    "text": TextPropertyItem,
    "float": FloatPropertyItem,
    "int": IntPropertyItem,
    "bool": BoolPropertyItem,
}


class _SortableItem(QTableWidgetItem):
    """A cell that sorts by a key of its own, so "100%" comes after "83%"."""

    def __init__(self, text: str, key) -> None:
        super().__init__(text)
        self.key = key

    def __lt__(self, other) -> bool:
        if isinstance(other, _SortableItem):
            return self.key < other.key
        return super().__lt__(other)


class PatternView(InstanceView, PatternViewMixin):
    """
    Edits one pattern as a graph of nodes.

    Each leaf statement of the pattern is a node; double-clicking one expands it into
    its expression tree. Selecting a node shows its constraints in the property panel,
    where a statement can be made optional or a wildcard and weighted, a constant
    loosened or pinned, a load resized, an operator widened to a set. Saving writes the
    pattern into ``kb.patterns``, where the PatternOutliner pass picks it up
    on the next decompilation.

    What the view does is :class:`~angrmanagement.present.patterns.PatternViewMixin`'s; this class gives it its
    widgets.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("pattern", workspace, default_docking_position, instance)
        self.base_caption = "Pattern"

        self._init_pattern_state()
        self.hovered_block: QPatternNode | None = None

        self._graph_widget: QPatternGraph
        self._properties: QPropertyEditor
        self._status: QLabel
        self._undo_btn: QPushButton
        self._loosen_btn: QPushButton
        self._save_btn: QPushButton
        self._nodes_by_path: dict[NodePath, QPatternNode] = {}
        self._library: QPatternLibrary
        self._apply_btn: QPushButton
        self._matches_table: QTableWidget
        self._search_here_btn: QPushButton
        self._search_all_btn: QPushButton
        self._suggest_btn: QPushButton
        self._item_keys: dict[int, tuple[str, Any]] = {}
        self._model: PropertyModel | None = None
        self._tabs: QTabWidget
        self._min_size: QSpinBox
        self._min_identity: QDoubleSpinBox
        self._statements: QComboBox
        self._discover_btn: QPushButton
        self._families_table: QTableWidget
        self._discover_status: QLabel

        self._init_widgets()
        self.width_hint = 900
        self.height_hint = 600
        self.updateGeometry()

    @staticmethod
    def minimumSizeHint() -> QSize:
        return QSize(400, 300)

    #
    # hooks of the mixin
    #

    def _code_view_class(self) -> Any:
        # imported here: the code view's widget imports this view, so a top-level import is a cycle
        from angrmanagement.ui.views.code_view import CodeView  # pylint:disable=import-outside-toplevel

        return CodeView

    def redraw_graph(self) -> None:
        self._graph_widget.refresh()

    def _show_tab(self, name: str) -> None:
        self._tabs.setCurrentWidget(self._discover_tab if name == "discover" else self._pattern_tab)

    def _set_status(self, text: str) -> None:
        self._status.setText(text)

    def _set_discover_status(self, text: str) -> None:
        self._discover_status.setText(text)

    def _discover_settings(self) -> tuple[int, float, Any]:
        return self._min_size.value(), self._min_identity.value(), self._statements.currentData()

    #
    # the project's patterns
    #

    def reload_library(self) -> None:
        self._library.reload()

    @property
    def _library_table(self) -> QTableWidget:
        return self._library.table

    def library_selection(self) -> StoredPattern | None:
        return self._library.selection()

    def toggle_stored(self, stored: StoredPattern) -> None:
        self._library.toggle(stored)

    def delete_stored(self, stored: StoredPattern) -> None:
        self._library.delete(stored)

    def export_stored(self, stored: StoredPattern, path: str) -> None:
        self._library.export(stored, path)

    def import_stored(self, path: str) -> StoredPattern:
        return self._library.import_(path)

    #
    # discovery
    #

    def family_at(self, row: int) -> int | None:
        """The index into ``families`` of a table row, which sorting moves around."""
        item = self._families_table.item(row, 0) if row >= 0 else None
        return None if item is None else item.data(Qt.ItemDataRole.UserRole)

    def _family_found(self, index: int) -> None:
        column = 4
        for row in range(self._families_table.rowCount()):
            if self.family_at(row) == index:
                text, key = found_cell(self.families[index])
                item = self._families_table.item(row, column)
                # the key first: with sorting on, setText moves the row right away
                item.key = key
                item.setText(text)
                break

    def _families_changed(self) -> None:
        table = self._families_table
        # rows move while sorting is on; fill with it off, then sort once
        table.setSortingEnabled(False)
        table.setRowCount(len(self.families))
        for i, f in enumerate(self.families):
            for j, (text, key) in enumerate(family_cells(f)):
                item = _SortableItem(text, key)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if j == 0:
                    item.setData(Qt.ItemDataRole.UserRole, i)
                table.setItem(i, j, item)
        table.setSortingEnabled(True)

    def _matches_changed(self) -> None:
        table = self._matches_table
        table.setRowCount(len(self.matches))
        for i, r in enumerate(self.matches):
            for j, text in enumerate(match_cells(r)):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(i, j, item)

    #
    # widgets
    #

    def _init_widgets(self) -> None:
        self._graph_widget = QPatternGraph(self)
        self._properties = QPropertyEditor()

        self._undo_btn = QPushButton("Undo")
        self._undo_btn.clicked.connect(self.undo)
        self._loosen_btn = QPushButton("Loosen constants")
        self._loosen_btn.setToolTip("Let every constant match any value")
        self._loosen_btn.clicked.connect(self.loosen_constants)
        self._cut_btn = QPushButton("Cut deep expressions")
        self._cut_btn.setToolTip("Wildcard subexpressions below the depth shape search can see")
        self._cut_btn.clicked.connect(self.cut_depth)
        self._captures_btn = QPushButton("Loosen interior captures")
        self._captures_btn.setToolTip("Stop requiring interior values to flow through one variable")
        self._captures_btn.clicked.connect(self.loosen_interior_captures)
        self._save_btn = QPushButton("Save to project")
        self._save_btn.clicked.connect(self.save)
        self._apply_btn = QPushButton("Save && Redecompile")
        self._apply_btn.setToolTip("Turn the pattern on, save it, then decompile its function again with it applied")
        self._apply_btn.clicked.connect(self.apply)
        buttons = QHBoxLayout()
        buttons.addWidget(self._undo_btn)
        buttons.addWidget(self._loosen_btn)
        buttons.addWidget(self._cut_btn)
        buttons.addWidget(self._captures_btn)
        buttons.addWidget(self._save_btn)
        buttons.addWidget(self._apply_btn)
        buttons.addStretch()

        self._library = QPatternLibrary(
            self.workspace, self.instance, on_edit=self.edit_stored, on_status=self._set_status
        )

        self._status = QLabel("no pattern loaded")
        self._status.setWordWrap(True)

        self._search_here_btn = QPushButton("Search this function")
        self._search_here_btn.clicked.connect(self.search_current_function)
        self._search_all_btn = QPushButton("Search all functions")
        self._search_all_btn.clicked.connect(self.search_all_functions)
        search_buttons = QHBoxLayout()
        search_buttons.addWidget(self._search_here_btn)
        search_buttons.addWidget(self._search_all_btn)
        search_buttons.addStretch()

        self._matches_table = QTableWidget(0, 6)
        self._matches_table.setHorizontalHeaderLabels(
            ["Function", "Where", "Similarity", "Identity", "Verified", "Outlinable"]
        )
        self._matches_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._matches_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._matches_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._matches_table.cellDoubleClicked.connect(lambda row, _col: self.jump_to_match(row))
        self._matches_table.cellClicked.connect(lambda row, _col: self.show_match(row))
        self._suggest_btn = QPushButton("Use suggested sub-run")
        self._suggest_btn.setToolTip("Re-lift the pattern from the single-entry part of the selected occurrence")
        self._suggest_btn.clicked.connect(lambda: self.use_suggestion(self._matches_table.currentRow()))
        search_buttons.addWidget(self._suggest_btn)

        side = QWidget()
        side_layout = QVBoxLayout()
        side_layout.setContentsMargins(3, 3, 3, 3)
        side_layout.addWidget(QLabel("Project patterns"))
        side_layout.addWidget(self._library, 1)
        side_layout.addWidget(self._properties, 2)
        side_layout.addLayout(buttons)
        side_layout.addLayout(search_buttons)
        side_layout.addWidget(self._matches_table, 1)
        side_layout.addWidget(self._status)
        side.setLayout(side_layout)
        self._pattern_tab = side

        self._tabs = QTabWidget()
        self._tabs.addTab(side, "Pattern")
        self._discover_tab = self._init_discover_tab()
        self._tabs.addTab(self._discover_tab, "Discover")

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._graph_widget)
        splitter.addWidget(self._tabs)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)
        self.setLayout(layout)

    def _on_family_open(self, row: int) -> None:
        index = self.family_at(row)
        if index is not None:
            self.open_family(index)

    def selected_families(self) -> list[int]:
        """Indices into ``families`` of the selected rows, in table order."""
        rows = sorted({index.row() for index in self._families_table.selectedIndexes()})
        return [i for i in (self.family_at(r) for r in rows) if i is not None]

    def families_context_menu(self) -> QMenu:
        return to_qmenu(self.families_menu(self.selected_families()), self._families_table)

    def _init_discover_tab(self) -> QWidget:
        self._min_size = QSpinBox()
        self._min_size.setRange(2, 256)
        self._min_size.setValue(DEFAULT_MIN_SIZE)
        self._min_size.setToolTip("Fewest statements a family's copies must have; gotos do not count")
        self._min_identity = QDoubleSpinBox()
        self._min_identity.setRange(0.3, 1.0)
        self._min_identity.setSingleStep(0.05)
        self._min_identity.setValue(DEFAULT_MIN_IDENTITY)
        self._min_identity.setToolTip("How alike the copies of a family must be")
        self._statements = QComboBox()
        for label, mode, tip in STATEMENT_MODES:
            self._statements.addItem(label, mode)
            self._statements.setItemData(self._statements.count() - 1, tip, Qt.ItemDataRole.ToolTipRole)
        self._statements.setToolTip("How the statements of one copy may follow each other")
        # a copy that is one straight run of pseudocode is what a reader recognizes as repeated code
        self._statements.setCurrentIndex(self._statements.findData(DEFAULT_STATEMENTS))
        self._discover_btn = QPushButton("Discover in current function")
        self._discover_btn.setToolTip("Find families of similar code in the function shown in the pseudocode view")
        self._discover_btn.clicked.connect(self.workspace.discover_patterns)
        knobs = QHBoxLayout()
        knobs.addWidget(QLabel("Min statements"))
        knobs.addWidget(self._min_size)
        knobs.addWidget(QLabel("Min identity"))
        knobs.addWidget(self._min_identity)
        knobs.addWidget(QLabel("Statements"))
        knobs.addWidget(self._statements)
        knobs.addWidget(self._discover_btn)
        knobs.addStretch()

        self._families_table = QTableWidget(0, 6)
        self._families_table.setHorizontalHeaderLabels(["Copies", "Size", "Identity", "Outlinable", "Found", "Where"])
        self._families_table.horizontalHeaderItem(4).setToolTip(
            "Verified occurrences of the family's lifted pattern in the function, and how many of the "
            "family's own copies are among them"
        )
        self._families_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._families_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._families_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._families_table.setSortingEnabled(True)
        self._families_table.cellDoubleClicked.connect(lambda row, _col: self._on_family_open(row))
        self._families_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._families_table.customContextMenuRequested.connect(
            lambda pos: self.families_context_menu().exec(self._families_table.viewport().mapToGlobal(pos))
        )

        self._discover_status = QLabel("no discovery run yet")
        self._discover_status.setWordWrap(True)

        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(3, 3, 3, 3)
        layout.addLayout(knobs)
        layout.addWidget(self._families_table, 1)
        layout.addWidget(self._discover_status)
        tab.setLayout(layout)
        return tab

    #
    # graph
    #

    def _rebuild(self, recenter: bool = False) -> None:
        """Redraw everything. The graph keeps the selected node in place unless ``recenter``."""
        self._rebuild_graph(recenter)
        self._rebuild_properties()
        self._undo_btn.setEnabled(self.editor is not None and self.editor.can_undo)

    def _rebuild_graph(self, recenter: bool = False) -> None:
        self._nodes_by_path.clear()
        self.hovered_block = None
        if self.editor is None:
            self._graph_widget.graph = None
            return
        tree, _ = pattern_tree(self.editor, self.collapsed)

        def convert(ref: PatternNodeRef, converted: dict) -> QPatternNode:
            if ref not in converted:
                converted[ref] = self._make_node(ref.path, ref.node, ref.kind)
            return converted[ref]

        self._graph_widget.set_graph(convert_graph(tree, convert), anchor=None if recenter else self.selected_path)

    def _make_node(self, path: NodePath, node, kind: str) -> QPatternNode:
        item = QPatternNode(self, path, node, kind)
        self._nodes_by_path[path] = item
        return item

    #
    # properties
    #

    def _rebuild_properties(self) -> None:
        self._item_keys.clear()
        root = GroupPropertyItem("Root")
        for group in self.property_groups():
            root.addChild(self._group_item(group))
        model = PropertyModel(root)
        model.valueChanged.connect(self._on_property_changed)
        self._model = model
        self._properties.setModel(model)

    def _item(self, item, key: tuple[str, Any]):
        self._item_keys[id(item)] = key
        return item

    def _group_item(self, group: PropertyGroup) -> GroupPropertyItem:
        item = GroupPropertyItem(group.name, description=group.description)
        for spec in group.items:
            item.addChild(self._item(self._property_item(spec), spec.key))
        return item

    @staticmethod
    def _property_item(spec: PropertySpec):
        if spec.kind == "combo":
            return ComboPropertyItem(
                spec.label, spec.value, spec.choices, description=spec.description, readonly=spec.readonly
            )
        return _PROPERTY_ITEMS[spec.kind](spec.label, spec.value, description=spec.description, readonly=spec.readonly)

    def _on_property_changed(self, item, *_) -> None:
        key = self._item_keys.get(id(item))
        if key is None or self.editor is None:
            return
        self.set_property(key, item.value)
