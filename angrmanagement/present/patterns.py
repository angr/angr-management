"""
The pattern view without a toolkit.

The view edits one pattern (angr's ``PatternEditor``) as a graph of nodes: each leaf statement is a node, and a
statement's expression tree hangs under it unless collapsed. Selecting a node shows its constraints in a property
sheet; the editor's operations loosen or cut the pattern; saving writes it into ``kb.patterns``. The view also lists the
project's patterns, searches for the pattern in this or every function, and discovers families of similar code in a
function, from which a pattern can be lifted.

:class:`PatternViewMixin` is all of that over hooks a frontend's view gives (its graph, property sheet, tables and
status line); the Qt ``PatternView`` and the terminal's :class:`PatternPresenter` are both one.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

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
    PReturn,
    PStore,
    PUnaryOp,
    PVVar,
    dsl,
)
from angr.analyses.decompiler.known_patterns.dsl import PatternExpr
from angr.analyses.decompiler.known_patterns.edit import LEAF_MODES, PatternEditor, describe
from angr.analyses.decompiler.pattern_match import STATEMENTS_ANY, STATEMENTS_CONSECUTIVE, STATEMENTS_FOLLOW
from angr.knowledge_plugins.patterns import StoredPattern

from angrmanagement.data.jobs.job import JobState
from angrmanagement.data.jobs.pattern_discovery import PatternDiscoveryJob, PatternFoundJob
from angrmanagement.data.jobs.pattern_search import PatternSearchJob, current_decompilation
from angrmanagement.logic import GlobalInfo

from .base import InstancePresenter, ask_open_files
from .graphs import GraphBox, TreeGraphPresenter
from .keymap import Binding, Keymap
from .menus import Menu, MenuEntry
from .spans import Line
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from angr.analyses.decompiler.known_patterns import KnownPattern
    from angr.analyses.decompiler.known_patterns.dsl import PatternNode
    from angr.analyses.decompiler.known_patterns.edit import NodePath

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.jobs.pattern_discovery import DiscoveredFamily, DiscoveryResult
    from angrmanagement.data.jobs.pattern_search import PatternMatchRow

_l = logging.getLogger(__name__)

NO_EARLIER_FORM = (
    "This wildcard has been one since the pattern was lifted, so there is nothing to put back. "
    "Lift the pattern again from the pseudocode to pin it."
)

LEAF_TYPES = (PAssign, PStore, PCallStmt, PCondJump, PReturn, PAnyStmt)
#: The kinds of node: a leaf statement's mode, or an expression (a wildcard one or not).
LEAF_KINDS = ("required", "optional", "wildcard")
#: The style key of each kind of node's box, from the Qt nodes' fills.
KIND_STYLES = {
    "required": "pattern.required",
    "optional": "pattern.optional",
    "wildcard": "pattern.wildcard",
    "expr": "pattern.expr",
    "wildcard-expr": "pattern.wildcard",
}
#: The frame of a leaf that failed verification in the selected occurrence.
FAILED_BORDER_STYLE = "pattern.failed.border"
#: How a discovered copy's statements may follow each other: caption, mode, description.
STATEMENT_MODES = [
    ("Any order", STATEMENTS_ANY, "A copy may take statements from anywhere in the function's block order"),
    (
        "Follow control flow",
        STATEMENTS_FOLLOW,
        "A copy continues only into a block that follows in the control flow",
    ),
    (
        "Consecutive only",
        STATEMENTS_CONSECUTIVE,
        "A copy is one straight run of code: consecutive pseudocode lines",
    ),
]
#: The discovery knobs' defaults: fewest statements, least identity, and (a straight run of pseudocode being what a
#: reader recognizes as repeated code) consecutive statements.
DEFAULT_MIN_SIZE = 6
DEFAULT_MIN_IDENTITY = 0.6
DEFAULT_STATEMENTS = STATEMENTS_CONSECUTIVE


def _bytes(n: int) -> str:
    return f"{n} byte" if n == 1 else f"{n} bytes"


def _callee(names: frozenset[str]) -> str:
    return "|".join(sorted(names)) or "*"


def node_label(node: PatternNode) -> str:  # pylint: disable=too-many-branches
    """The AIL class a node matches, then what it constrains; describe() for the rest."""
    if isinstance(node, dsl.PAnyStmt):
        label = "Statement (any)"
    elif isinstance(node, dsl.PAssign):
        label = "Assignment"
    elif isinstance(node, dsl.PStore):
        label = "Store" + (f" {_bytes(node.size)}" if node.size is not None else "")
    elif isinstance(node, dsl.PCallStmt):
        label = "Call " + _callee(node.call.names)
    elif isinstance(node, dsl.PCondJump):
        label = "ConditionalJump"
    elif isinstance(node, dsl.PReturn):
        label = "Return" if node.values is not None else "Return (any values)"
    elif isinstance(node, dsl.PAny):
        label = "Expression (any)"
    elif isinstance(node, dsl.PVVar):
        label = "VirtualVariable" + (f" {node.bits} bits" if node.bits is not None else "")
    elif isinstance(node, dsl.PConst):
        if node.symbol is not None:
            label = f"Const &{node.symbol}"
        elif node.value is not None:
            label = f"Const {node.value:#x}" if node.value >= 0 else f"Const {node.value}"
        else:
            label = "Const (any)"
    elif isinstance(node, (dsl.PBinOp, dsl.PUnaryOp)):
        ops = node.op if isinstance(node.op, str) else "|".join(sorted(node.op))
        label = f"{'BinaryOp' if isinstance(node, dsl.PBinOp) else 'UnaryOp'} {ops}"
    elif isinstance(node, dsl.PLoad):
        label = "Load" + (f" {_bytes(node.size)}" if node.size is not None else "")
    elif isinstance(node, dsl.PConv):
        sizes = f" {node.from_bits} to {node.to_bits} bits" if node.from_bits and node.to_bits else ""
        label = "Convert" + sizes
    elif isinstance(node, dsl.PExtract):
        label = "Extract" + (f" {node.bits} bits" if node.bits is not None else "")
    elif isinstance(node, dsl.PCall):
        label = "Call " + _callee(node.names)
    elif isinstance(node, dsl.PPhi):
        label = "Phi"
    elif isinstance(node, dsl.PITE):
        label = "ITE"
    else:
        return describe(node)
    name = getattr(node, "name", None)
    return f"{label} [{name}]" if name else label


def node_detail(node: PatternNode, kind: str, collapsed: bool) -> str:
    """A node's second line: a leaf's mode, weight and whether it is collapsed; an expression's whether it is."""
    if kind in LEAF_KINDS:
        weight = node.weight  # type: ignore[union-attr]
        parts = [kind]
        if weight != 1.0:
            parts.append(f"weight {weight:g}")
        if isinstance(node, PAnyStmt):
            return ", ".join(parts)
        if collapsed:
            parts.append("collapsed")
        return ", ".join(parts)
    return "collapsed" if collapsed else ""


@dataclass(eq=False)
class PatternNodeRef:
    """A node shown in the graph: where it is in the pattern, the pattern node, and its kind."""

    path: Any
    node: Any
    kind: str


def pattern_tree(editor: PatternEditor, collapsed: set[Any]) -> tuple[networkx.DiGraph, dict[Any, PatternNodeRef]]:
    """
    The graph the view shows: the leaf statements in order, each followed by the next, with the expression tree of
    each leaf that is not collapsed under it. Returns the graph and its nodes by path.
    """
    graph: networkx.DiGraph = networkx.DiGraph()
    by_path: dict[Any, PatternNodeRef] = {}

    def make(path, node, kind: str) -> PatternNodeRef:
        ref = PatternNodeRef(path, node, kind)
        by_path[path] = ref
        graph.add_node(ref)
        return ref

    def add_expressions(parent: PatternNodeRef, path) -> None:
        for child_path, child in editor.children(path):
            ref = make(child_path, child, "wildcard-expr" if isinstance(child, PAny) else "expr")
            graph.add_edge(parent, ref)
            if child_path not in collapsed:
                add_expressions(ref, child_path)

    previous: PatternNodeRef | None = None
    for path, leaf in editor.leaves():
        ref = make(path, leaf, PatternEditor.leaf_mode(leaf))
        if previous is not None:
            graph.add_edge(previous, ref)
        previous = ref
        if path not in collapsed:
            add_expressions(ref, path)
    return graph, by_path


#
# The property sheet
#


@dataclass
class PropertySpec:
    """
    A row of the property sheet: its kind (``text``, ``float``, ``int``, ``bool`` or ``combo``), label, value, what
    setting it does (``key``, as :meth:`PatternViewMixin._apply_property` takes it), and help.
    """

    kind: str
    label: str
    value: Any
    key: tuple[str, Any]
    description: str = ""
    readonly: bool = False
    choices: list[str] = field(default_factory=list)


@dataclass
class PropertyGroup:
    """A group of the property sheet: its name, what it is about, and its rows."""

    name: str
    description: str
    items: list[PropertySpec] = field(default_factory=list)


#
# The project's patterns
#


def toggle_stored(instance: Instance, stored: StoredPattern) -> str:
    """Turn a stored pattern on or off; returns what to tell the user."""
    instance.kb.patterns.set_enabled(stored.name, not stored.enabled)  # type: ignore[union-attr]
    state = "on" if stored.enabled else "off"
    return f"{stored.name} is {state}; it applies the next time a function is decompiled"


def delete_stored(instance: Instance, stored: StoredPattern) -> str:
    instance.kb.patterns.remove(stored.name)  # type: ignore[union-attr]
    return f"deleted {stored.name}"


def export_stored(stored: StoredPattern, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stored.to_dict(), f, indent=1)
    return f"exported {stored.name} to {path}"


def import_stored(instance: Instance, path: str) -> tuple[StoredPattern, str]:
    with open(path, encoding="utf-8") as f:
        stored = StoredPattern.from_dict(json.load(f))
    instance.kb.patterns.store(stored)  # type: ignore[union-attr]
    return stored, f"imported {stored.name} from {path}"


class ProjectPatternsModel(ListTableModel[Any]):
    """The project's patterns, as the pattern view's library lists them; Enabled is a check box."""

    COLUMNS: ClassVar[list[Column]] = [
        Column("Pattern", 20),
        Column("Call", 16),
        Column("Enabled", 9, checkable=True),
        Column("Min similarity", 8, align="right"),
        Column("From", 10, stretch=True),
    ]
    ENABLED = 2

    def __init__(self, view: PatternViewMixin) -> None:
        super().__init__()
        self.view = view

    def reload(self) -> None:
        kb = self.view.instance.kb
        self.set_rows([] if kb is None else sorted(kb.patterns, key=lambda p: p.name))

    def column_text(self, obj: Any, col: int) -> str:
        name = self.COLUMNS[col].name
        if name == "Pattern":
            return obj.name
        if name == "Call":
            return obj.pattern.call_name
        if name == "Enabled":
            return "on" if obj.enabled else "off"
        if name == "Min similarity":
            return f"{obj.min_similarity:.0%}"
        return f"{obj.origin_func:#x}" if obj.origin_func is not None else ""

    def is_checked(self, obj: Any, col: int) -> bool:
        return col == self.ENABLED and bool(obj.enabled)

    def set_checked(self, row: int, col: int, checked: bool) -> bool:
        stored = self.row(row)
        if stored is None or col != self.ENABLED:
            return False
        if checked != stored.enabled:
            self.view.toggle_stored(stored)
        return True

    def key_of(self, obj: Any) -> Any:
        return obj.name

    def on_activate(self, obj: Any) -> None:
        self.view.edit_stored(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        selected = self.objects(rows)
        return Menu("Patterns", [MenuEntry("Edit pattern...", lambda: self.view.edit_stored(selected[0]))])


#
# Searching and discovery
#


def match_cells(r: PatternMatchRow) -> list[str]:
    """A match table row: function, where, similarity, identity, verified (with the failed leaves), outlinable."""
    where = f"{r.start_addr:#x}" if r.start_addr is not None else "?"
    if r.end_addr is not None and r.end_addr != r.start_addr:
        where += f"..{r.end_addr:#x}"
    failed = "" if r.verified else " (" + ", ".join(str(i) for i in r.failed_leaves[:6]) + ")"
    outlinable = "yes" if r.outlinable else r.reason
    if r.suggested_start is not None and r.suggested_end is not None:
        outlinable += f"; try {r.suggested_start:#x}..{r.suggested_end:#x} ({r.suggested_coverage:.0%})"
    return [
        r.func_name,
        where,
        f"{r.similarity:.0%}",
        f"{r.identity:.0%}",
        "yes" if r.verified else "no" + failed,
        outlinable,
    ]


def found_cell(f: DiscoveredFamily) -> tuple[str, int]:
    """The families table's Found cell and its sort key: "-" for a family with no pattern, "…" until counted."""
    if f.pattern is None:
        return "-", -2
    if f.found is None:
        return "…", -1
    return f"{f.found} ({f.covered}/{f.copies} copies)", f.found


def family_cells(f: DiscoveredFamily) -> list[tuple[str, Any]]:
    """A families table row: copies, size, identity, outlinable, found and where, each with its sort key."""
    where = f"{f.start_addr:#x}" if f.start_addr is not None else "?"
    return [
        (str(f.copies), f.copies),
        (str(f.size), f.size),
        (f"{f.identity:.0%}", f.identity),
        (f"{f.outlinable}/{f.copies}", f.outlinable),
        found_cell(f),
        (where, f.start_addr if f.start_addr is not None else -1),
    ]


class MatchesModel(ListTableModel[Any]):
    """The occurrences of the last search; a row's activation jumps to it."""

    COLUMNS: ClassVar[list[Column]] = [
        Column("Function", 16),
        Column("Where", 20),
        Column("Similarity", 6, align="right"),
        Column("Identity", 6, align="right"),
        Column("Verified", 10),
        Column("Outlinable", stretch=True),
    ]

    def __init__(self, view: PatternViewMixin) -> None:
        super().__init__()
        self.view = view

    def column_text(self, obj: Any, col: int) -> str:
        return match_cells(obj)[col]

    def on_activate(self, obj: Any) -> None:
        self.view.jump_to_match(self.view.matches.index(obj))


class FamiliesModel(ListTableModel[int]):
    """The families the last discovery found; the rows are indices into ``families``."""

    COLUMNS: ClassVar[list[Column]] = [
        Column("Copies", 6, align="right"),
        Column("Size", 5, align="right"),
        Column("Identity", 8, align="right"),
        Column("Outlinable", 10),
        Column("Found", 20),
        Column("Where", stretch=True),
    ]

    def __init__(self, view: PatternViewMixin) -> None:
        super().__init__()
        self.view = view

    def column_text(self, obj: int, col: int) -> str:
        return family_cells(self.view.families[obj])[col][0]

    def column_value(self, obj: int, col: int) -> Any:
        return family_cells(self.view.families[obj])[col][1]

    def on_activate(self, obj: int) -> None:
        self.view.open_family(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        return self.view.families_menu(self.objects(rows))


#
# The view
#


def pattern_keymap() -> Keymap:
    """The pattern graph's keys, for what the Qt graph does with the mouse."""
    return Keymap(
        "pattern",
        [
            Binding("Shift+F10", "context_menu", "Context menu"),
            Binding("E", "expand_all", "Expand all"),
            Binding("C", "collapse_all", "Collapse all"),
            Binding("U", "undo", "Undo"),
        ],
    )


class PatternViewMixin:
    """
    The pattern view's state and actions. The class it is mixed into gives ``workspace`` and ``instance`` and the
    hooks between :meth:`_rebuild` and :meth:`_discover_settings`.
    """

    #: past this many nodes a fully expanded tree is unreadable and slow to lay out
    MAX_EXPANDED_NODES = 400

    workspace: Any
    instance: Instance
    editor: PatternEditor | None
    origin_func: int | None
    enabled: bool
    min_similarity: float
    require_verified: bool
    failed_leaves: set[int]
    selected_path: Any
    collapsed: set[Any]
    matches: list[PatternMatchRow]
    families: list[DiscoveredFamily]
    discovered_func: int | None
    _found_job: PatternFoundJob | None

    def _init_pattern_state(self) -> None:
        self.editor = None
        self.origin_func = None
        self.enabled = True
        self.min_similarity = 0.8
        self.require_verified = True
        self.failed_leaves = set()
        self.selected_path = None
        #: nodes whose subtree is hidden; everything else is shown
        self.collapsed = set()
        self.matches = []
        #: families found by the last discovery run, and the function they were found in
        self.families = []
        self.discovered_func = None
        #: the background job filling the Found column, cancelled when a newer discovery replaces it
        self._found_job = None

    #
    # Hooks
    #

    def _rebuild(self, recenter: bool = False) -> None:
        """Show the pattern again: the graph (keeping the selected node in place unless ``recenter``) and the
        property sheet."""
        raise NotImplementedError

    def _rebuild_properties(self) -> None:
        raise NotImplementedError

    def _set_status(self, text: str) -> None:
        raise NotImplementedError

    def redraw_graph(self) -> None:
        """The nodes' looks changed (the failed leaves)."""

    def _show_tab(self, name: str) -> None:
        """Bring the ``pattern`` or the ``discover`` tab to the front."""

    def _set_discover_status(self, text: str) -> None:
        raise NotImplementedError

    def _matches_changed(self) -> None:
        """The match table's rows changed."""

    def _families_changed(self) -> None:
        """The families table's rows changed."""

    def _family_found(self, index: int) -> None:
        """Family ``index``'s Found count arrived."""

    def _discover_settings(self) -> tuple[int, float, Any]:  # pylint: disable=no-self-use
        """The discovery knobs: fewest statements, least identity, how statements may follow each other."""
        return DEFAULT_MIN_SIZE, DEFAULT_MIN_IDENTITY, DEFAULT_STATEMENTS

    def _code_view_class(self) -> Any:  # pylint: disable=no-self-use
        """The view class to create a pseudocode view with, when the frontend has to name one."""
        return None

    #
    # Loading
    #

    def load_pattern(
        self,
        pattern: KnownPattern,
        origin_func: int | None = None,
        min_similarity: float = 0.8,
        enabled: bool = False,
        require_verified: bool = True,
    ) -> None:
        # a new pattern is saved off; it applies once turned on or saved with Save & Redecompile
        self.editor = PatternEditor(pattern)
        self.origin_func = origin_func
        self.min_similarity = min_similarity
        self.enabled = enabled
        self.require_verified = require_verified
        self.failed_leaves = set()
        # the last search's rows went with the pattern they were found for
        self.matches = []
        self._matches_changed()
        self.selected_path = None
        self.collapsed = self._default_collapsed()
        self._rebuild()
        note = "; too large to show expanded, double-click a statement to expand it" if self.collapsed else ""
        self._set_status(f"editing {pattern.name}: {len(self.editor.leaves())} statements{note}")

    def load_stored(self, stored: StoredPattern) -> None:
        self.load_pattern(
            stored.pattern,
            origin_func=stored.origin_func,
            min_similarity=stored.min_similarity,
            enabled=stored.enabled,
            require_verified=stored.require_verified,
        )

    #
    # Nodes
    #

    def select_node(self, path: NodePath) -> None:
        self.selected_path = path
        self._rebuild_properties()
        self.redraw_graph()

    def activate_node(self, path: NodePath) -> None:
        """Double-click: a node with children, statement or expression, expands or collapses.
        It never edits the pattern; wildcarding is the property panel's job."""
        if self.editor is None or not self.editor.children(path):
            return
        if path in self.collapsed:
            self.collapsed.discard(path)
        else:
            self.collapsed.add(path)
        self.selected_path = path
        self._rebuild()

    def expand_all(self) -> None:
        """Show every node, however large the tree."""
        if self.editor is None:
            return
        self.collapsed = set()
        self._rebuild(recenter=True)

    def collapse_all(self) -> None:
        """Show the statements only."""
        if self.editor is None:
            return
        self.collapsed = {path for path, _ in self.editor.leaves() if self.editor.children(path)}
        self._rebuild(recenter=True)

    def _default_collapsed(self) -> set[NodePath]:
        """Nothing collapsed, unless the full tree is too big; then only statements show."""
        if self.editor is None:
            return set()
        count = 0
        stack = [path for path, _ in self.editor.leaves()]
        while stack and count <= self.MAX_EXPANDED_NODES:
            path = stack.pop()
            count += 1
            stack.extend(child for child, _ in self.editor.children(path))
        if count <= self.MAX_EXPANDED_NODES:
            return set()
        return {path for path, _ in self.editor.leaves()}

    def _path_exists(self, path: NodePath) -> bool:
        assert self.editor is not None
        try:
            self.editor.node_at(path)
        except (AttributeError, IndexError, KeyError, TypeError):
            return False
        return True

    def leaf_index(self, path: NodePath) -> int:
        """The template's index of the leaf at ``path``, or -1."""
        if self.editor is None:
            return -1
        for i, (leaf_path, _) in enumerate(self.editor.leaves()):
            if leaf_path == path:
                return i
        return -1

    def is_failed(self, ref: PatternNodeRef) -> bool:
        """The leaf failed verification in the occurrence selected in the match table."""
        return ref.kind in LEAF_KINDS and self.leaf_index(ref.path) in self.failed_leaves

    def graph_menu(self) -> Menu:
        """The graph's context menu."""
        return Menu("", [MenuEntry("Expand all", self.expand_all), MenuEntry("Collapse all", self.collapse_all)])

    #
    # Editing
    #

    def set_leaf_mode(self, path: NodePath, mode: str) -> None:
        if self.editor is None:
            return
        self.editor.set_leaf_mode(path, mode)
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
            self.collapsed = {p for p in self.collapsed if self._path_exists(p)}
            if self.selected_path is not None and not self._path_exists(self.selected_path):
                self.selected_path = None
            self._rebuild()

    def save(self) -> StoredPattern | None:
        """Write the pattern into the knowledge base, replacing one of the same name."""
        if self.editor is None:
            return None
        stored = self.instance.kb.patterns.add(  # type: ignore[union-attr]
            self.editor.pattern,
            enabled=self.enabled,
            min_similarity=self.min_similarity,
            origin_func=self.origin_func,
            require_verified=self.require_verified,
            replace=True,
        )
        self._set_status(f"saved {stored.name} to the project ({'enabled' if stored.enabled else 'disabled'})")
        self.workspace.on_patterns_changed()
        return stored

    def apply(self) -> StoredPattern | None:
        """Turn the pattern on, save it, then decompile its function afresh so the outliner pass runs on it.

        Other functions pick the pattern up the next time they are decompiled without a
        cached result; their caches are left alone.
        """
        if self.editor is not None and not self.enabled:
            self.enabled = True
            self._rebuild_properties()
        stored = self.save()
        if stored is None:
            return None
        func = self._origin_function()
        if func is None:
            return stored
        code_view = self.workspace._get_or_create_view(  # pylint: disable=protected-access
            "pseudocode", self._code_view_class(), position="center"
        )
        if code_view is None:
            return stored
        code_view.function = func
        code_view.decompile(reset_cache=True)
        self._set_status(f"applied {stored.name} (enabled): {func.name} is being decompiled again")
        return stored

    #
    # The property sheet
    #

    def property_groups(self) -> list[PropertyGroup]:
        """The sheet's groups: the pattern's, and the selected node's (when it has constraints)."""
        groups: list[PropertyGroup] = []
        if self.editor is not None:
            groups.append(self._pattern_group_spec())
            if self.selected_path is not None and self._path_exists(self.selected_path):
                group = self._node_group_spec(self.selected_path)
                if group is not None:
                    groups.append(group)
        return groups

    def _pattern_group_spec(self) -> PropertyGroup:
        assert self.editor is not None
        pattern = self.editor.pattern
        group = PropertyGroup("Pattern", "The call the occurrences become, and when to apply it.")
        items = group.items
        items.append(PropertySpec("text", "Name", pattern.name, ("name", None)))
        items.append(PropertySpec("text", "Call name", pattern.call_name, ("call_name", None)))
        items.append(PropertySpec("text", "Display name", pattern.display_name, ("display_name", None)))
        returnty = pattern.returnty if isinstance(pattern.returnty, str) else ""
        items.append(PropertySpec("text", "Return type", returnty, ("returnty", None)))
        for param in pattern.params:
            ty = param.type if isinstance(param.type, str) else ""
            items.append(PropertySpec("text", f"Type of {param.capture}", ty, ("param_type", param.capture)))
        items.append(PropertySpec("float", "Min similarity", self.min_similarity, ("min_similarity", None)))
        items.append(PropertySpec("bool", "Enabled", self.enabled, ("enabled", None)))
        items.append(
            PropertySpec("bool", "Require structural match", self.require_verified, ("require_verified", None))
        )
        return group

    def _node_group_spec(self, path: NodePath) -> PropertyGroup | None:
        assert self.editor is not None
        node = self.editor.node_at(path)
        group = PropertyGroup("Selected node", "Constraints of the selected node.")
        items = group.items
        if isinstance(node, LEAF_TYPES):
            mode = PatternEditor.leaf_mode(node)
            # a statement that has always been a wildcard has no shape to go back to
            stuck = isinstance(node, PAnyStmt) and self.editor.restorable(path) is None
            items.append(
                PropertySpec(
                    "combo",
                    "Mode",
                    mode,
                    ("leaf_mode", path),
                    NO_EARLIER_FORM if stuck else "Whether an occurrence must contain this statement.",
                    readonly=stuck,
                    choices=list(LEAF_MODES),
                )
            )
            items.append(PropertySpec("float", "Weight", node.weight, ("weight", path)))
            if isinstance(node, PStore):
                items.append(PropertySpec("int", "Size (0 = any)", node.size or 0, ("size", path)))
            return group
        if not isinstance(node, PatternExpr):
            return None
        stuck = isinstance(node, PAny) and self.editor.restorable(path) is None
        items.append(
            PropertySpec(
                "bool",
                "Wildcard",
                isinstance(node, PAny),
                ("wildcard", path),
                NO_EARLIER_FORM if stuck else "Match any expression here.",
                readonly=stuck,
            )
        )
        if isinstance(node, PConst):
            value = "" if node.value is None else hex(node.value)
            items.append(PropertySpec("text", "Value (blank = any)", value, ("const_value", path)))
            items.append(PropertySpec("text", "Symbol (blank = none)", node.symbol or "", ("const_symbol", path)))
            items.append(PropertySpec("int", "Bits (0 = any)", node.bits or 0, ("const_bits", path)))
        elif isinstance(node, PVVar):
            items.append(PropertySpec("int", "Bits (0 = any)", node.bits or 0, ("vvar_bits", path)))
        elif isinstance(node, PLoad):
            items.append(PropertySpec("int", "Size (0 = any)", node.size or 0, ("size", path)))
        elif isinstance(node, (PBinOp, PUnaryOp)):
            ops = node.op if isinstance(node.op, str) else "|".join(sorted(node.op))
            items.append(PropertySpec("text", "Operators (a|b|c)", ops, ("ops", path)))
        return group

    def set_property(self, key: tuple[str, Any], value: Any) -> None:
        """A property was changed to ``value``: apply it, or say why not, and show the pattern as it is."""
        if self.editor is None:
            return
        what, path = key
        try:
            self._apply_property(what, path, value)
        except (TypeError, ValueError, KeyError) as ex:
            self._set_status(f"not applied: {ex}")
        # either way, show the pattern as it is, not the value that was typed
        self._rebuild()

    def _apply_property(self, what: str, path: Any, value: Any) -> None:  # pylint: disable=too-many-branches
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
            elif not ed.restore_node(path):
                raise ValueError(NO_EARLIER_FORM)
        elif what == "const_value":
            # a value replaces a symbol: the two are alternative ways to pin the constant
            text = str(value).strip()
            node = ed.node_at(path)
            assert isinstance(node, PConst)
            ed.set_const(path, int(text, 0) if text else None, node.bits, symbol=None if text else node.symbol)
        elif what == "const_symbol":
            text = str(value).strip()
            node = ed.node_at(path)
            assert isinstance(node, PConst)
            ed.set_const(path, None if text else node.value, node.bits, symbol=text or None)
        elif what == "const_bits":
            node = ed.node_at(path)
            assert isinstance(node, PConst)
            ed.set_const(path, node.value, int(value) or None, symbol=node.symbol)
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

    #
    # The project's patterns
    #

    def reload_library(self) -> None:
        """The project's patterns changed."""

    def edit_stored(self, stored: StoredPattern) -> None:
        self.load_stored(stored)

    def _patterns_changed(self, message: str) -> None:
        """The project's patterns changed: every view listing them hears of it, then the user."""
        self.workspace.on_patterns_changed()
        self._set_status(message)

    def toggle_stored(self, stored: StoredPattern) -> None:
        self._patterns_changed(toggle_stored(self.instance, stored))

    def delete_stored(self, stored: StoredPattern) -> None:
        self._patterns_changed(delete_stored(self.instance, stored))

    def export_stored(self, stored: StoredPattern, path: str) -> None:
        self._set_status(export_stored(stored, path))

    def import_stored(self, path: str) -> StoredPattern:
        stored, message = import_stored(self.instance, path)
        self._patterns_changed(message)
        return stored

    #
    # Searching
    #

    def search(self, functions, blocking: bool = False) -> None:
        """Look for the pattern as it stands in ``functions``; results land in the table."""
        if self.editor is None:
            return
        job = PatternSearchJob(
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
            f
            for f in self.instance.kb.functions.values()  # type: ignore[union-attr]
            if not (f.is_simprocedure or f.is_plt or f.is_alignment)
        ]
        self.search(funcs)

    def show_match(self, row: int) -> None:
        """Mark the leaves that failed verification in the selected occurrence."""
        self.failed_leaves = set(self.matches[row].failed_leaves) if 0 <= row < len(self.matches) else set()
        self.redraw_graph()

    def use_suggestion(self, row: int) -> bool:
        """Re-lift the pattern from the suggested sub-run of the selected occurrence, keeping
        the call name and settings. Returns whether a pattern was loaded."""
        if self.editor is None or row < 0 or row >= len(self.matches):
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
        """A pattern from the statements of ``func_addr`` between two instruction
        addresses, or None when the function cannot be decompiled."""
        from angr.analyses.decompiler.known_patterns.generator import (  # pylint:disable=import-outside-toplevel
            PatternGenerationError,
            PatternGenerator,
        )
        from angr.analyses.decompiler.pattern_match.search import (  # pylint:disable=import-outside-toplevel
            tokenize_for_templates,
        )

        func = self.instance.kb.functions.get(func_addr)  # type: ignore[union-attr]
        if func is None:
            return None
        try:
            dec = current_decompilation(self.instance, func)
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
            return PatternGenerator(dec.codegen, dec.ail_graph).generate_pattern_from_statements(stmts, call_name)
        except PatternGenerationError as ex:
            self._set_status(f"cannot lift a pattern from that range: {ex}")
            return None

    def jump_to_match(self, row: int) -> None:
        if 0 <= row < len(self.matches) and self.matches[row].start_addr is not None:
            self.workspace.jump_to(self.matches[row].start_addr)

    def _origin_function(self):
        if self.origin_func is None:
            return None
        return self.instance.kb.functions.get(self.origin_func)  # type: ignore[union-attr]

    def _show_matches(self, rows: list[PatternMatchRow]) -> None:
        self.matches = rows
        self._matches_changed()
        verified = sum(1 for r in rows if r.verified)
        self._set_status(f"{len(rows)} occurrence(s), {verified} verified")

    #
    # Discovery
    #

    def show_discover_tab(self) -> None:
        self._show_tab("discover")

    def discover(self, func, blocking: bool = True) -> None:
        """Look for families of similar code in ``func``; the results land in the Discover tab."""
        if self._found_job is not None:
            self._found_job.state = JobState.CANCELLED
            self._found_job = None
        self._show_tab("discover")
        min_size, min_identity, statements = self._discover_settings()
        job = PatternDiscoveryJob(
            self.instance,
            func,
            min_size=min_size,
            min_identity=min_identity,
            on_finish=self._show_families,
            blocking=blocking,
            statements=statements,
        )
        self._set_discover_status(f"discovering in {func.name}...")
        self.workspace.job_manager.add_job(job)

    def load_family(self, index: int) -> bool:
        """Edit the pattern lifted from a discovered family. Returns whether one was loaded."""
        if index < 0 or index >= len(self.families):
            return False
        family = self.families[index]
        if family.pattern is None:
            self._set_discover_status("nothing in this family's first copy can be lifted into a pattern")
            return False
        self.load_pattern(family.pattern, origin_func=self.discovered_func)
        self._show_tab("pattern")
        return True

    def open_family(self, index: int) -> None:
        """Show the family in the pseudocode view: every copy's lines highlighted, the cursor on the first."""
        self.open_families([index])

    def open_families(self, indices: list[int]) -> None:
        """Highlight every copy of the families in the pseudocode view, the cursor on the first family's."""
        families = [self.families[i] for i in indices if 0 <= i < len(self.families)]
        if not families or self.discovered_func is None:
            return
        func = self.instance.kb.functions.get(self.discovered_func)  # type: ignore[union-attr]
        if func is None:
            return
        self.workspace.decompile_function(func, curr_ins=families[0].start_addr)
        code_view = self.workspace.view_manager.first_view_in_category("pseudocode")
        if code_view is not None:
            code_view.highlight_pattern(func.addr, [addrs for f in families for addrs in f.copy_addrs])
            self.workspace.raise_view(code_view)

    def highlight_families_in_disassembly(self, indices: list[int]) -> None:
        """Paint every instruction of every copy of the families in the disassembly view."""
        addrs: set[int] = set()
        for i in indices:
            if 0 <= i < len(self.families):
                addrs.update(*self.families[i].copy_addrs)
        if addrs:
            self.workspace.highlight_in_disassembly(addrs)

    def families_menu(self, indices: list[int]) -> Menu:
        """The families table's menu for the families ``indices``."""
        return Menu(
            "",
            [
                MenuEntry(
                    "Highlight patterns in pseudocode", lambda: self.open_families(indices), enabled=bool(indices)
                ),
                MenuEntry(
                    "Highlight patterns in disassembly",
                    lambda: self.highlight_families_in_disassembly(indices),
                    enabled=bool(indices),
                ),
                MenuEntry(
                    "Edit pattern...",
                    lambda: self.load_family(indices[0]),
                    enabled=len(indices) == 1 and self.families[indices[0]].pattern is not None,
                ),
            ],
        )

    def _on_family_found(self, result: DiscoveryResult, index: int, found: int, covered: int) -> None:
        """A background count for one family arrived; ignored if the table has moved on."""
        if index < 0 or index >= len(result.families):
            return
        family = result.families[index]
        family.found, family.covered = found, covered
        if self.families is not result.families:
            return
        self._family_found(index)

    def _show_families(self, result: DiscoveryResult) -> None:
        self.families = result.families
        self.discovered_func = result.func_addr
        self._families_changed()
        # the Found column is filled in the background, cheapest patterns first
        if self._found_job is not None:
            self._found_job.state = JobState.CANCELLED
        self._found_job = PatternFoundJob(self.instance, result, lambda i, n, c: self._on_family_found(result, i, n, c))
        self.workspace.job_manager.add_job(self._found_job)
        self._set_discover_status(
            f"{len(result.families)} famil{'y' if len(result.families) == 1 else 'ies'} in {result.func_name} "
            f"({result.tokens} statements, {result.seconds:.1f}s)"
        )


class PatternPresenter(PatternViewMixin, InstancePresenter):
    """
    The pattern view of a frontend that draws its own widgets: the graph as a :class:`TreeGraphPresenter`, the
    library, matches and families as table models, and the status lines as text. The frontend view gives
    ``properties_changed``, ``status_changed`` and ``show_tab`` if it wants to hear of those.
    """

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        InstancePresenter.__init__(self, workspace, "pattern", instance, default_docking_position)
        self.base_caption = "Pattern"
        self._init_pattern_state()
        self.status = "no pattern loaded"
        self.discover_status = "no discovery run yet"
        self.min_size = DEFAULT_MIN_SIZE
        self.min_identity = DEFAULT_MIN_IDENTITY
        self.statements: Any = DEFAULT_STATEMENTS
        self.nodes_by_path: dict[Any, PatternNodeRef] = {}
        self._tree: networkx.DiGraph | None = None
        self.graph = TreeGraphPresenter(lambda: self._tree, self._box, "graph", node_sorter=lambda boxes: boxes)
        self.library = ProjectPatternsModel(self)
        self.library.reload()
        self.matches_model = MatchesModel(self)
        self.families_model = FamiliesModel(self)
        #: called after the graph (with ``recenter``) or the looks of its nodes changed
        self.on_graph_changed: Callable[[bool], None] | None = None

    @property
    def keymap(self) -> Keymap:
        return pattern_keymap()

    def _notify(self, name: str, *args) -> None:
        handler = getattr(self.view, name, None)
        if handler is not None:
            handler(*args)

    def _rebuild(self, recenter: bool = False) -> None:
        if self.editor is None:
            self._tree, self.nodes_by_path = None, {}
        else:
            self._tree, self.nodes_by_path = pattern_tree(self.editor, self.collapsed)
        self.graph.selected = self.nodes_by_path.get(self.selected_path)
        self.graph.invalidate()
        if self.on_graph_changed is not None:
            self.on_graph_changed(recenter)
        self._rebuild_properties()

    def _rebuild_properties(self) -> None:
        self._notify("properties_changed")

    def _set_status(self, text: str) -> None:
        self.status = text
        self._notify("status_changed")

    def _set_discover_status(self, text: str) -> None:
        self.discover_status = text
        self._notify("status_changed")

    def redraw_graph(self) -> None:
        self.graph.selected = self.nodes_by_path.get(self.selected_path)
        self.graph.invalidate()
        if self.on_graph_changed is not None:
            self.on_graph_changed(False)

    def _show_tab(self, name: str) -> None:
        self._notify("show_tab", name)

    def _matches_changed(self) -> None:
        self.matches_model.set_rows(list(self.matches))

    def _families_changed(self) -> None:
        self.families_model.set_rows(list(range(len(self.families))))

    def _family_found(self, index: int) -> None:
        row = self.families_model.index_of(index)
        if row is not None:
            self.families_model.rows_changed(row, row)

    def _discover_settings(self) -> tuple[int, float, Any]:
        return self.min_size, self.min_identity, self.statements

    def reload_library(self) -> None:
        self.library.reload()

    def _box(self, ref: PatternNodeRef) -> GraphBox:
        lines = [Line().append(node_label(ref.node))]
        detail = node_detail(ref.node, ref.kind, ref.path in self.collapsed)
        if detail:
            lines.append(Line().append(detail, "pattern.detail"))
        border = FAILED_BORDER_STYLE if self.is_failed(ref) else ""
        return GraphBox(ref, lines, 0, KIND_STYLES[ref.kind], border)

    # what the graph widget does with a box
    def select_ref(self, ref: PatternNodeRef) -> None:
        self.select_node(ref.path)

    def activate(self, ref: PatternNodeRef) -> None:
        self.activate_node(ref.path)

    def context_menu(self, ref: PatternNodeRef | None = None) -> Menu | None:  # pylint: disable=unused-argument
        return self.graph_menu()

    def discover_in_current_function(self) -> None:
        self.workspace.discover_patterns()

    def ask_export(self, stored: StoredPattern) -> None:
        """Ask where to export ``stored`` to, then export it."""

        def then(path: str | None) -> None:
            if path:
                self.export_stored(stored, path)

        GlobalInfo.ui_services.pick_save_file_async("Export pattern", f"{stored.name}.json", "JSON (*.json)", then)

    def ask_import(self) -> None:
        """Ask for a pattern file, then import it."""

        def then(paths: list[str]) -> None:
            if paths:
                self.import_stored(paths[0])

        ask_open_files("Import pattern", "", "JSON (*.json)", False, then)


__all__ = [
    "DEFAULT_MIN_IDENTITY",
    "DEFAULT_MIN_SIZE",
    "DEFAULT_STATEMENTS",
    "FAILED_BORDER_STYLE",
    "KIND_STYLES",
    "LEAF_KINDS",
    "LEAF_TYPES",
    "NO_EARLIER_FORM",
    "STATEMENT_MODES",
    "FamiliesModel",
    "MatchesModel",
    "PatternNodeRef",
    "PatternPresenter",
    "PatternViewMixin",
    "ProjectPatternsModel",
    "PropertyGroup",
    "PropertySpec",
    "delete_stored",
    "export_stored",
    "family_cells",
    "found_cell",
    "import_stored",
    "match_cells",
    "node_detail",
    "node_label",
    "pattern_keymap",
    "pattern_tree",
    "toggle_stored",
]
