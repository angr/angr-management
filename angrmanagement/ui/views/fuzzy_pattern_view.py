from __future__ import annotations

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
from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QSplitter, QVBoxLayout, QWidget

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
    from angr.knowledge_plugins.fuzzy_patterns import StoredPattern

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
        self.selected_path: NodePath | None = None
        self.expanded: set[NodePath] = set()
        self.hovered_block: QFuzzyPatternNode | None = None

        self._graph_widget: QFuzzyPatternGraph
        self._properties: QPropertyEditor
        self._status: QLabel
        self._undo_btn: QPushButton
        self._save_btn: QPushButton
        self._nodes_by_path: dict[NodePath, QFuzzyPatternNode] = {}
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
        self, pattern: KnownPattern, origin_func: int | None = None, min_similarity: float = 0.8, enabled: bool = True
    ) -> None:
        self.editor = PatternEditor(pattern)
        self.origin_func = origin_func
        self.min_similarity = min_similarity
        self.enabled = enabled
        self.selected_path = None
        self.expanded.clear()
        self._rebuild()
        self._set_status(f"editing {pattern.name}: {len(self.editor.leaves())} statements")

    def load_stored(self, stored: StoredPattern) -> None:
        self.load_pattern(
            stored.pattern, origin_func=stored.origin_func, min_similarity=stored.min_similarity, enabled=stored.enabled
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
            replace=True,
        )
        self._set_status(f"saved {stored.name} to the project ({'enabled' if stored.enabled else 'disabled'})")
        return stored

    def redraw_graph(self) -> None:
        self._graph_widget.refresh()

    #
    # widgets
    #

    def _init_widgets(self) -> None:
        self._graph_widget = QFuzzyPatternGraph(self)
        self._properties = QPropertyEditor()

        self._undo_btn = QPushButton("Undo")
        self._undo_btn.clicked.connect(self.undo)
        self._save_btn = QPushButton("Save to project")
        self._save_btn.clicked.connect(self.save)
        buttons = QHBoxLayout()
        buttons.addWidget(self._undo_btn)
        buttons.addWidget(self._save_btn)
        buttons.addStretch()

        self._status = QLabel("no pattern loaded")
        self._status.setWordWrap(True)

        side = QWidget()
        side_layout = QVBoxLayout()
        side_layout.setContentsMargins(3, 3, 3, 3)
        side_layout.addWidget(self._properties, 1)
        side_layout.addLayout(buttons)
        side_layout.addWidget(self._status)
        side.setLayout(side_layout)

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
