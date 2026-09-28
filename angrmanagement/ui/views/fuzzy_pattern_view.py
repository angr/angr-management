from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import networkx
from angr.analyses.decompiler.known_patterns import (
    PAny,
    PAnyStmt,
    PAssign,
    PBinOp,
    PCallStmt,
    PCondJump,
    PConst,
    PLoad,
    PStore,
    PUnaryOp,
    PVVar,
)
from angr.analyses.decompiler.known_patterns.dsl import PatternExpr
from angr.analyses.decompiler.known_patterns.edit import LEAF_MODES, PatternEditor
from angr.knowledge_plugins.fuzzy_patterns import StoredPattern
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.data.jobs.fuzzy_pattern_search import FuzzyMatchRow, FuzzyPatternSearchJob
from angrmanagement.ui.views.view import InstanceView
from angrmanagement.ui.widgets.qfuzzy_pattern_graph import QFuzzyPatternGraph, QFuzzyPatternNode
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
    from angr.analyses.decompiler.known_patterns import KnownPattern, PatternNode
    from angr.analyses.decompiler.known_patterns.edit import NodePath

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace

_l = logging.getLogger(__name__)

LEAF_TYPES = (PAssign, PStore, PCallStmt, PCondJump, PAnyStmt)


class FuzzyPatternView(InstanceView):
    """
    Edits one fuzzy pattern as a graph of nodes.

    Each leaf statement of the pattern is a node; double-clicking one expands it into
    its expression tree. Selecting a node shows its constraints in the property panel,
    where a statement can be made optional or a wildcard and weighted, a constant
    loosened or pinned, a load resized, an operator widened to a set. Saving writes the
    pattern into ``kb.fuzzy_patterns``, where the FuzzyPatternOutliner pass picks it up
    on the next decompilation.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("fuzzy_pattern", workspace, default_docking_position, instance)
        self.base_caption = "Fuzzy Pattern"

        self.editor: PatternEditor | None = None
        self.origin_func: int | None = None
        self.enabled: bool = True
        self.min_similarity: float = 0.8
        self.require_verified: bool = True
        self.failed_leaves: set[int] = set()
        self.selected_path: NodePath | None = None
        self.expanded: set[NodePath] = set()
        self.hovered_block: QFuzzyPatternNode | None = None

        self._graph_widget: QFuzzyPatternGraph
        self._properties: QPropertyEditor
        self._status: QLabel
        self._undo_btn: QPushButton
        self._loosen_btn: QPushButton
        self._save_btn: QPushButton
        self._nodes_by_path: dict[NodePath, QFuzzyPatternNode] = {}
        self.matches: list[FuzzyMatchRow] = []
        self._library_table: QTableWidget
        self._apply_btn: QPushButton
        self._library_rows: list[StoredPattern] = []
        self._matches_table: QTableWidget
        self._search_here_btn: QPushButton
        self._search_all_btn: QPushButton
        self._suggest_btn: QPushButton
        self._item_keys: dict[int, tuple[str, Any]] = {}
        self._model: PropertyModel | None = None

        self._init_widgets()
        self.width_hint = 900
        self.height_hint = 600
        self.updateGeometry()

    @staticmethod
    def minimumSizeHint() -> QSize:
        return QSize(400, 300)

    #
    # loading
    #

    def load_pattern(
        self,
        pattern: KnownPattern,
        origin_func: int | None = None,
        min_similarity: float = 0.8,
        enabled: bool = True,
        require_verified: bool = True,
    ) -> None:
        self.editor = PatternEditor(pattern)
        self.origin_func = origin_func
        self.min_similarity = min_similarity
        self.enabled = enabled
        self.require_verified = require_verified
        self.failed_leaves = set()
        self.matches = []
        self.selected_path = None
        self.expanded.clear()
        self._rebuild()
        self._set_status(f"editing {pattern.name}: {len(self.editor.leaves())} statements")

    def load_stored(self, stored: StoredPattern) -> None:
        self.load_pattern(
            stored.pattern,
            origin_func=stored.origin_func,
            min_similarity=stored.min_similarity,
            enabled=stored.enabled,
            require_verified=stored.require_verified,
        )

    #
    # node interaction (called by the canvas)
    #

    def select_node(self, path: NodePath) -> None:
        self.selected_path = path
        self._rebuild_properties()
        self.redraw_graph()

    def activate_node(self, path: NodePath) -> None:
        """Double-click: a leaf expands or collapses; an expression becomes a wildcard."""
        if self.editor is None:
            return
        node = self.editor.node_at(path)
        if isinstance(node, LEAF_TYPES):
            if isinstance(node, PAnyStmt):
                return
            if path in self.expanded:
                self.expanded.discard(path)
            else:
                self.expanded.add(path)
            self.selected_path = path
            self._rebuild()
            return
        if isinstance(node, PatternExpr) and not isinstance(node, PAny):
            self.editor.set_expr_wildcard(path)
            self.selected_path = path
            self._rebuild()

    def set_leaf_mode(self, path: NodePath, mode: str) -> None:
        if self.editor is None:
            return
        self.editor.set_leaf_mode(path, mode)
        if mode == "wildcard":
            self.expanded.discard(path)
        self._rebuild()

    def loosen_constants(self) -> int:
        """Drop every pinned constant value, the usual first edit on a lifted pattern."""
        if self.editor is None:
            return 0
        n = self.editor.loosen_constants()
        self._rebuild()
        self._set_status(f"loosened {n} constant(s)")
        return n

    def cut_depth(self) -> int:
        """Wildcard everything below the depth shape search can see."""
        if self.editor is None:
            return 0
        n = self.editor.cut_depth()
        self._rebuild()
        self._set_status(f"cut {n} deep subexpression(s)")
        return n

    def loosen_interior_captures(self) -> int:
        """Stop requiring interior values to flow through one variable."""
        if self.editor is None:
            return 0
        n = self.editor.loosen_interior_captures()
        self._rebuild()
        self._set_status(f"loosened {n} interior capture(s)")
        return n

    def undo(self) -> None:
        if self.editor is not None and self.editor.undo():
            self.expanded = {p for p in self.expanded if self._path_exists(p)}
            if self.selected_path is not None and not self._path_exists(self.selected_path):
                self.selected_path = None
            self._rebuild()

    def save(self) -> StoredPattern | None:
        """Write the pattern into the knowledge base, replacing one of the same name."""
        if self.editor is None:
            return None
        stored = self.instance.kb.fuzzy_patterns.add(
            self.editor.pattern,
            enabled=self.enabled,
            min_similarity=self.min_similarity,
            origin_func=self.origin_func,
            require_verified=self.require_verified,
            replace=True,
        )
        self._set_status(f"saved {stored.name} to the project ({'enabled' if stored.enabled else 'disabled'})")
        self.reload_library()
        return stored

    def apply(self) -> StoredPattern | None:
        """Save, then decompile the pattern's function afresh so the outliner pass runs on it.

        Other functions pick the pattern up the next time they are decompiled without a
        cached result; their caches are left alone.
        """
        stored = self.save()
        if stored is None:
            return None
        func = self._origin_function()
        if func is None:
            return stored
        # imported here: the code view's widget imports this view, so a top-level import is a cycle
        from angrmanagement.ui.views.code_view import CodeView  # pylint:disable=import-outside-toplevel

        code_view = self.workspace._get_or_create_view("pseudocode", CodeView, position="center")
        code_view.function = func
        code_view.decompile(reset_cache=True)
        self._set_status(f"applied {stored.name}: {func.name} is being decompiled again")
        return stored

    def leaf_index(self, path: NodePath) -> int:
        """The template's index of the leaf at ``path``, or -1."""
        if self.editor is None:
            return -1
        for i, (leaf_path, _) in enumerate(self.editor.leaves()):
            if leaf_path == path:
                return i
        return -1

    def redraw_graph(self) -> None:
        self._graph_widget.refresh()

    #
    # the project's patterns
    #

    def reload_library(self) -> None:
        self._library_rows = sorted(self.instance.kb.fuzzy_patterns, key=lambda p: p.name)
        table = self._library_table
        table.setRowCount(len(self._library_rows))
        for i, stored in enumerate(self._library_rows):
            origin = f"{stored.origin_func:#x}" if stored.origin_func is not None else ""
            cells = [
                stored.name,
                stored.pattern.call_name,
                "on" if stored.enabled else "off",
                f"{stored.min_similarity:.0%}",
                origin,
            ]
            for j, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(i, j, item)

    def library_selection(self) -> StoredPattern | None:
        rows = {index.row() for index in self._library_table.selectedIndexes()}
        if len(rows) != 1:
            return None
        row = next(iter(rows))
        return self._library_rows[row] if 0 <= row < len(self._library_rows) else None

    def edit_stored(self, stored: StoredPattern) -> None:
        self.load_stored(stored)

    def toggle_stored(self, stored: StoredPattern) -> None:
        self.instance.kb.fuzzy_patterns.set_enabled(stored.name, not stored.enabled)
        self.reload_library()

    def delete_stored(self, stored: StoredPattern) -> None:
        self.instance.kb.fuzzy_patterns.remove(stored.name)
        self.reload_library()
        self._set_status(f"deleted {stored.name}")

    def export_stored(self, stored: StoredPattern, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(stored.to_dict(), f, indent=1)
        self._set_status(f"exported {stored.name} to {path}")

    def import_stored(self, path: str) -> StoredPattern:
        with open(path, encoding="utf-8") as f:
            stored = StoredPattern.from_dict(json.load(f))
        self.instance.kb.fuzzy_patterns.store(stored)
        self.reload_library()
        self._set_status(f"imported {stored.name} from {path}")
        return stored

    def _on_library_edit(self) -> None:
        stored = self.library_selection()
        if stored is not None:
            self.edit_stored(stored)

    def _on_library_toggle(self) -> None:
        stored = self.library_selection()
        if stored is not None:
            self.toggle_stored(stored)

    def _on_library_delete(self) -> None:
        stored = self.library_selection()
        if stored is not None:
            self.delete_stored(stored)

    def _on_library_export(self) -> None:
        stored = self.library_selection()
        if stored is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export fuzzy pattern", f"{stored.name}.json", "JSON (*.json)")
        if path:
            self.export_stored(stored, path)

    def _on_library_import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import fuzzy pattern", "", "JSON (*.json)")
        if path:
            self.import_stored(path)

    #
    # searching
    #

    def search(self, functions, blocking: bool = False) -> None:
        """Look for the pattern as it stands in ``functions``; results land in the table."""
        if self.editor is None:
            return
        job = FuzzyPatternSearchJob(
            self.instance, self.editor.pattern, list(functions), on_finish=self._show_matches, blocking=blocking
        )
        self._set_status(f"searching {len(job.functions)} function(s)...")
        self.workspace.job_manager.add_job(job)

    def search_current_function(self) -> None:
        func = self._origin_function()
        if func is not None:
            self.search([func])

    def search_all_functions(self) -> None:
        funcs = [
            f for f in self.instance.kb.functions.values() if not (f.is_simprocedure or f.is_plt or f.is_alignment)
        ]
        self.search(funcs)

    def show_match(self, row: int) -> None:
        """Mark the leaves that failed verification in the selected occurrence."""
        self.failed_leaves = set(self.matches[row].failed_leaves) if 0 <= row < len(self.matches) else set()
        self.redraw_graph()

    def use_suggestion(self, row: int) -> bool:
        """Re-lift the pattern from the suggested sub-run of the selected occurrence, keeping
        the call name and settings. Returns whether a pattern was loaded."""
        if self.editor is None or not (0 <= row < len(self.matches)):
            return False
        r = self.matches[row]
        if r.suggested_start is None or r.suggested_end is None:
            self._set_status("this occurrence has no suggested sub-run")
            return False
        pattern = self.lift_from_range(r.func_addr, r.suggested_start, r.suggested_end, self.editor.pattern.call_name)
        if pattern is None:
            return False
        self.load_pattern(
            pattern,
            origin_func=r.func_addr,
            min_similarity=self.min_similarity,
            enabled=self.enabled,
            require_verified=self.require_verified,
        )
        self._set_status(f"pattern re-lifted from {r.suggested_start:#x}..{r.suggested_end:#x} in {r.func_name}")
        return True

    def lift_from_range(self, func_addr: int, start_addr: int, end_addr: int, call_name: str):
        """A fuzzy pattern from the statements of ``func_addr`` between two instruction
        addresses, or None when the function cannot be decompiled."""
        from angr.analyses.decompiler.known_patterns.generator import (  # pylint:disable=import-outside-toplevel
            PatternGenerationError,
            PatternGenerator,
        )
        from angr.analyses.fuzzy_patterns.search import tokenize_for_templates  # pylint:disable=import-outside-toplevel

        func = self.instance.kb.functions.get(func_addr)
        if func is None:
            return None
        try:
            dec = self.instance.project.analyses.Decompiler(func, cfg=self.instance.cfg, use_cache=True)
        except Exception:  # pylint:disable=broad-except
            _l.warning("Decompiling %s to re-lift the pattern failed", func.name, exc_info=True)
            return None
        if dec.ail_graph is None or dec.codegen is None:
            return None
        entry = next((b for b in dec.ail_graph if b.addr == func.addr and b.idx is None), None)
        if entry is None:
            return None
        stream = tokenize_for_templates(dec.ail_graph, entry, kb=self.instance.kb)
        blocks = {(b.addr, b.idx): b for b in stream.blocks}
        stmts = [
            blocks[loc.block_loc].statements[loc.stmt_idx]
            for loc in stream.locs
            if loc.ins_addr is not None and start_addr <= loc.ins_addr <= end_addr
        ]
        try:
            return PatternGenerator(dec.codegen, dec.ail_graph).generate_fuzzy_from_statements(stmts, call_name)
        except PatternGenerationError as ex:
            self._set_status(f"cannot lift a pattern from that range: {ex}")
            return None

    def jump_to_match(self, row: int) -> None:
        if 0 <= row < len(self.matches) and self.matches[row].start_addr is not None:
            self.workspace.jump_to(self.matches[row].start_addr)

    def _origin_function(self):
        if self.origin_func is None:
            return None
        return self.instance.kb.functions.get(self.origin_func)

    def _show_matches(self, rows: list[FuzzyMatchRow]) -> None:
        self.matches = rows
        table = self._matches_table
        table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            where = f"{r.start_addr:#x}" if r.start_addr is not None else "?"
            if r.end_addr is not None and r.end_addr != r.start_addr:
                where += f"..{r.end_addr:#x}"
            failed = "" if r.verified else " (" + ", ".join(str(i) for i in r.failed_leaves[:6]) + ")"
            outlinable = "yes" if r.outlinable else r.reason
            if r.suggested_start is not None and r.suggested_end is not None:
                outlinable += f"; try {r.suggested_start:#x}..{r.suggested_end:#x} ({r.suggested_coverage:.0%})"
            cells = [
                r.func_name,
                where,
                f"{r.similarity:.0%}",
                f"{r.identity:.0%}",
                "yes" if r.verified else "no" + failed,
                outlinable,
            ]
            for j, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                table.setItem(i, j, item)
        verified = sum(1 for r in rows if r.verified)
        self._set_status(f"{len(rows)} occurrence(s), {verified} verified")

    #
    # widgets
    #

    def _init_widgets(self) -> None:
        self._graph_widget = QFuzzyPatternGraph(self)
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
        self._apply_btn = QPushButton("Apply")
        self._apply_btn.setToolTip("Save, then decompile the pattern's function again with the pattern applied")
        self._apply_btn.clicked.connect(self.apply)
        buttons = QHBoxLayout()
        buttons.addWidget(self._undo_btn)
        buttons.addWidget(self._loosen_btn)
        buttons.addWidget(self._cut_btn)
        buttons.addWidget(self._captures_btn)
        buttons.addWidget(self._save_btn)
        buttons.addWidget(self._apply_btn)
        buttons.addStretch()

        self._library_table = QTableWidget(0, 5)
        self._library_table.setHorizontalHeaderLabels(["Pattern", "Call", "Enabled", "Min similarity", "From"])
        self._library_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._library_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._library_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._library_table.cellDoubleClicked.connect(lambda _row, _col: self._on_library_edit())
        library_buttons = QHBoxLayout()
        for label, handler in (
            ("Edit", self._on_library_edit),
            ("On/off", self._on_library_toggle),
            ("Delete", self._on_library_delete),
            ("Export...", self._on_library_export),
            ("Import...", self._on_library_import),
        ):
            btn = QPushButton(label)
            btn.clicked.connect(handler)
            library_buttons.addWidget(btn)
        library_buttons.addStretch()

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
        side_layout.addWidget(self._library_table, 1)
        side_layout.addLayout(library_buttons)
        side_layout.addWidget(self._properties, 2)
        side_layout.addLayout(buttons)
        side_layout.addLayout(search_buttons)
        side_layout.addWidget(self._matches_table, 1)
        side_layout.addWidget(self._status)
        side.setLayout(side_layout)
        self.reload_library()

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._graph_widget)
        splitter.addWidget(side)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)
        self.setLayout(layout)

    def _set_status(self, text: str) -> None:
        self._status.setText(text)

    def _path_exists(self, path: NodePath) -> bool:
        assert self.editor is not None
        try:
            self.editor.node_at(path)
        except (AttributeError, IndexError, KeyError, TypeError):
            return False
        return True

    #
    # graph
    #

    def _rebuild(self) -> None:
        self._rebuild_graph()
        self._rebuild_properties()
        self._undo_btn.setEnabled(self.editor is not None and self.editor.can_undo)

    def _rebuild_graph(self) -> None:
        self._nodes_by_path.clear()
        self.hovered_block = None
        if self.editor is None:
            self._graph_widget.graph = None
            return
        graph: networkx.DiGraph = networkx.DiGraph()
        previous: QFuzzyPatternNode | None = None
        for path, leaf in self.editor.leaves():
            item = self._make_node(path, leaf, PatternEditor.leaf_mode(leaf))
            graph.add_node(item)
            if previous is not None:
                graph.add_edge(previous, item)
            previous = item
            if path in self.expanded:
                self._add_expression_nodes(graph, item, path)
        self._graph_widget.graph = graph

    def _add_expression_nodes(self, graph: networkx.DiGraph, parent: QFuzzyPatternNode, path: NodePath) -> None:
        assert self.editor is not None
        for child_path, child in self.editor.children(path):
            item = self._make_node(child_path, child, "wildcard-expr" if isinstance(child, PAny) else "expr")
            graph.add_node(item)
            graph.add_edge(parent, item)
            self._add_expression_nodes(graph, item, child_path)

    def _make_node(self, path: NodePath, node: PatternNode, kind: str) -> QFuzzyPatternNode:
        item = QFuzzyPatternNode(self, path, node, kind)
        self._nodes_by_path[path] = item
        return item

    #
    # properties
    #

    def _rebuild_properties(self) -> None:
        self._item_keys.clear()
        root = GroupPropertyItem("Root")
        if self.editor is not None:
            root.addChild(self._pattern_group())
            if self.selected_path is not None and self._path_exists(self.selected_path):
                group = self._node_group(self.selected_path)
                if group is not None:
                    root.addChild(group)
        model = PropertyModel(root)
        model.valueChanged.connect(self._on_property_changed)
        self._model = model
        self._properties.setModel(model)

    def _item(self, item, key: tuple[str, Any]):
        self._item_keys[id(item)] = key
        return item

    def _pattern_group(self) -> GroupPropertyItem:
        assert self.editor is not None
        pattern = self.editor.pattern
        group = GroupPropertyItem("Pattern", description="The call the occurrences become, and when to apply it.")
        group.addChild(self._item(TextPropertyItem("Name", pattern.name), ("name", None)))
        group.addChild(self._item(TextPropertyItem("Call name", pattern.call_name), ("call_name", None)))
        group.addChild(self._item(TextPropertyItem("Display name", pattern.display_name), ("display_name", None)))
        returnty = pattern.returnty if isinstance(pattern.returnty, str) else ""
        group.addChild(self._item(TextPropertyItem("Return type", returnty), ("returnty", None)))
        for param in pattern.params:
            ty = param.type if isinstance(param.type, str) else ""
            group.addChild(self._item(TextPropertyItem(f"Type of {param.capture}", ty), ("param_type", param.capture)))
        group.addChild(self._item(FloatPropertyItem("Min similarity", self.min_similarity), ("min_similarity", None)))
        group.addChild(self._item(BoolPropertyItem("Enabled", self.enabled), ("enabled", None)))
        group.addChild(
            self._item(BoolPropertyItem("Require structural match", self.require_verified), ("require_verified", None))
        )
        return group

    def _node_group(self, path: NodePath) -> GroupPropertyItem | None:
        assert self.editor is not None
        node = self.editor.node_at(path)
        group = GroupPropertyItem("Selected node", description="Constraints of the selected node.")
        if isinstance(node, LEAF_TYPES):
            mode = PatternEditor.leaf_mode(node)
            group.addChild(self._item(ComboPropertyItem("Mode", mode, list(LEAF_MODES)), ("leaf_mode", path)))
            group.addChild(self._item(FloatPropertyItem("Weight", node.weight), ("weight", path)))
            if isinstance(node, PStore):
                group.addChild(self._item(IntPropertyItem("Size (0 = any)", node.size or 0), ("size", path)))
            return group
        if not isinstance(node, PatternExpr):
            return None
        group.addChild(self._item(BoolPropertyItem("Wildcard", isinstance(node, PAny)), ("wildcard", path)))
        if isinstance(node, PConst):
            value = "" if node.value is None else hex(node.value)
            group.addChild(self._item(TextPropertyItem("Value (blank = any)", value), ("const_value", path)))
            group.addChild(self._item(IntPropertyItem("Bits (0 = any)", node.bits or 0), ("const_bits", path)))
        elif isinstance(node, PVVar):
            group.addChild(self._item(IntPropertyItem("Bits (0 = any)", node.bits or 0), ("vvar_bits", path)))
        elif isinstance(node, PLoad):
            group.addChild(self._item(IntPropertyItem("Size (0 = any)", node.size or 0), ("size", path)))
        elif isinstance(node, (PBinOp, PUnaryOp)):
            ops = node.op if isinstance(node.op, str) else "|".join(sorted(node.op))
            group.addChild(self._item(TextPropertyItem("Operators (a|b|c)", ops), ("ops", path)))
        return group

    def _on_property_changed(self, item, *_) -> None:
        key = self._item_keys.get(id(item))
        if key is None or self.editor is None:
            return
        what, path = key
        value = item.value
        try:
            self._apply_property(what, path, value)
        except (TypeError, ValueError, KeyError) as ex:
            self._set_status(f"not applied: {ex}")
            return
        self._rebuild()

    def _apply_property(self, what: str, path: Any, value: Any) -> None:
        assert self.editor is not None
        ed = self.editor
        if what == "name":
            ed.set_name(str(value))
        elif what == "call_name":
            ed.set_call_name(str(value))
        elif what == "display_name":
            ed.set_display_name(str(value))
        elif what == "returnty":
            ed.set_returnty(str(value) or None)
        elif what == "param_type":
            ed.set_param_type(path, str(value) or None)
        elif what == "min_similarity":
            self.min_similarity = max(0.0, min(1.0, float(value)))
        elif what == "enabled":
            self.enabled = bool(value)
        elif what == "require_verified":
            self.require_verified = bool(value)
        elif what == "leaf_mode":
            self.set_leaf_mode(path, str(value))
        elif what == "weight":
            ed.set_leaf_weight(path, float(value))
        elif what == "size":
            ed.set_load_size(path, int(value) or None)
        elif what == "wildcard":
            if value:
                ed.set_expr_wildcard(path)
        elif what == "const_value":
            text = str(value).strip()
            node = ed.node_at(path)
            assert isinstance(node, PConst)
            ed.set_const(path, int(text, 0) if text else None, node.bits)
        elif what == "const_bits":
            node = ed.node_at(path)
            assert isinstance(node, PConst)
            ed.set_const(path, node.value, int(value) or None)
        elif what == "vvar_bits":
            node = ed.node_at(path)
            assert isinstance(node, PVVar)
            ed.set_vvar(path, int(value) or None, node.categories)
        elif what == "ops":
            ops = [o.strip() for o in str(value).split("|") if o.strip()]
            if not ops:
                raise ValueError("at least one operator")
            ed.set_ops(path, ops[0] if len(ops) == 1 else frozenset(ops))
        else:
            raise KeyError(what)
