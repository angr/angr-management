"""
The data dependency view without a toolkit.

The view runs angr's DataDep analysis from the parameters a trace file gives (a final state, and optionally a start, an
end and blocks) and shows its graph: the full graph, the one without temporaries, or the dependencies of one node
(traced backward or forward). Hovering over a node highlights the edges from its ancestors (with Ctrl, to its
descendants). :func:`search_nodes` is the node search dialog's matching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from angr.analyses.data_dep import ConstantDepNode, MemDepNode, RegDepNode, TmpDepNode

from .base import InstancePresenter, project_of
from .graphs import GraphBox, TreeGraphPresenter
from .keymap import Binding, Keymap
from .menus import Menu, MenuEntry
from .spans import Line

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from angr.analyses.data_dep import BaseDepNode
    from networkx import DiGraph

    from angrmanagement.data.instance import Instance

#: The style keys of the blocks (as the Qt blocks fill them: constants green, temporaries pink, the others blue), and
#: of the edges on the traced path.
CONSTANT_STYLE = "datadep.constant"
TMP_STYLE = "datadep.tmp"
DEFAULT_STYLE = "datadep.node"
TRACED_EDGE_STYLE = "graph.edge.traced"
ANCESTOR_EDGE_STYLE = "graph.edge.ancestor"


def node_style(node: BaseDepNode) -> str:
    """The style key of a node's block, by its kind."""
    if isinstance(node, ConstantDepNode):
        return CONSTANT_STYLE
    if isinstance(node, TmpDepNode):
        return TMP_STYLE
    return DEFAULT_STYLE


def instruction_text(node: BaseDepNode, instr: Any) -> str:
    """A block's second line: the instruction, or the address and statement index."""
    if instr is not None:
        return f"{hex(instr.address)}: {instr.mnemonic} {instr.op_str}"
    return f"{hex(node.ins_addr)}:{node.stmt_idx}"


def node_lines(node: BaseDepNode, instr: Any) -> list[Line]:
    """A block's lines: the node in bold, then its instruction."""
    return [Line().append(str(node), "bold"), Line().append(instruction_text(node, instr))]


def node_tooltip(node: BaseDepNode) -> str | None:
    """A non-constant node's value (a constant shows its value already)."""
    if isinstance(node, ConstantDepNode):
        return None
    value: Any = node.value
    return f"Value: {hex(value)}"


def instruction_map(kb) -> dict[int, Any]:
    """Every instruction of every function the knowledge base knows, by address."""
    out: dict[int, Any] = {}
    for _, func in kb.functions.items():
        for block in func.blocks:
            for ins in block.disassembly.insns:
                out[ins.address] = ins
    return out


def ancestors(graph: DiGraph, node: Any) -> set[Any]:
    """``node`` and every node with a path to it."""
    out = {node}
    stack = [node]
    while stack:
        for pred in graph.predecessors(stack.pop()):
            if pred not in out:
                out.add(pred)
                stack.append(pred)
    return out


def descendants(graph: DiGraph, node: Any) -> set[Any]:
    """``node`` and every node it has a path to."""
    out = {node}
    stack = [node]
    while stack:
        for succ in graph.successors(stack.pop()):
            if succ not in out:
                out.add(succ)
                stack.append(succ)
    return out


def graph_has_tmp_nodes(graph: DiGraph | None) -> bool:
    return bool(graph) and any(isinstance(node, TmpDepNode) for node in graph.nodes)  # type: ignore[union-attr]


def search_nodes(nodes: Iterable[BaseDepNode], name: str, value: str, address: str) -> tuple[list[BaseDepNode], str]:
    """
    The nodes the search dialog matches: by part of their text, their value and their instruction's address (both in
    hex); every criterion given must match. Returns the matches and an error to show (empty when there is none).
    """
    try:
        val_as_int = int(value, 16) if value else None
        addr_as_int = int(address, 16) if address else None
    except ValueError:
        return [], "Input must be in hexadecimal format!"

    def matches(node: BaseDepNode) -> bool:
        ok = True
        if val_as_int:
            ok &= node.value == val_as_int
        if addr_as_int:
            ok &= node.ins_addr == addr_as_int
        if name:
            ok &= name in str(node)
        return ok

    found = [n for n in nodes if matches(n)]
    return found, "" if found else "No nodes match the given search criteria."


@dataclass
class NodeSearch:
    """The search dialog's state: the criteria, the nodes they match, and the one shown."""

    name: str = ""
    value: str = ""
    address: str = ""
    matches: list[Any] = field(default_factory=list)
    index: int = -1
    error: str = ""


def data_dep_keymap() -> Keymap:
    """The data dependency view's keys: Ctrl+F's search, and keys for what the Qt view does with the mouse."""
    return Keymap(
        "data_dependency",
        [
            Binding("Ctrl+F", "show_search", "Search for a node"),
            Binding("Shift+F10", "context_menu", "Context menu"),
            Binding("D", "toggle_trace_direction", "Trace descendants instead of ancestors (Ctrl while hovering)"),
            Binding("T", "toggle_graph", "Hide or show temporaries, or untrack the traced node"),
        ],
    )


class DataDepPresenter(InstancePresenter):
    """The data dependency view; setting :attr:`analysis_params` runs the analysis, as in Qt."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "data_dependency", instance, default_docking_position)
        self.base_caption = "Data Dependency"
        self._end_state = None
        self._start_addr: int | None = None
        self._end_addr: int | None = None
        self._block_addrs: list[int] | None = None
        self._data_dep: Any = None
        self._ddg: DiGraph | None = None
        self._instructions: dict[int, Any] = {}
        self.traced_ancestors: set[Any] = set()
        self.traced_descendants: set[Any] = set()
        #: whether hovering traces descendants (the Qt view's Ctrl)
        self.trace_descendants = False
        self.search = NodeSearch()
        self.graph = TreeGraphPresenter(lambda: self._ddg, self._box, "graph", node_sorter=lambda boxes: boxes)
        #: called after the graph changed, and after the traced nodes changed
        self.on_reloaded: Callable[[], None] | None = None
        self.on_traced: Callable[[], None] | None = None

    @property
    def keymap(self) -> Keymap:
        return data_dep_keymap()

    @property
    def data_dep_graph(self) -> DiGraph | None:
        return self._ddg

    @property
    def analysis_params(self) -> dict:
        return {
            "end_state": self._end_state,
            "start_addr": self._start_addr,
            "end_addr": self._end_addr,
            "block_addrs": self._block_addrs,
        }

    @analysis_params.setter
    def analysis_params(self, new_params: dict) -> None:
        if new_params == self.analysis_params:
            # Nothing new, no need to rerun analysis
            return
        try:
            self._end_state = new_params["end_state"]
            self._start_addr = new_params["start_addr"]
            self._end_addr = new_params["end_addr"]
            self._block_addrs = new_params["block_addrs"]
            self.run_analysis()
        except OSError:
            pass

    def run_analysis(self) -> None:
        project = project_of(self.instance)
        assert project is not None
        analyses: Any = project.analyses
        self._data_dep = analyses.DataDep(self._end_state, self._start_addr, self._end_addr, self._block_addrs)
        self._ddg = self._data_dep.graph
        self.reload()

    def reload(self) -> None:
        kb = self.instance.kb
        if kb is not None:
            self._instructions = instruction_map(kb)
        self.traced_ancestors = set()
        self.traced_descendants = set()
        self.graph.invalidate()
        if self.on_reloaded is not None:
            self.on_reloaded()

    def _box(self, node: BaseDepNode) -> GraphBox:
        instr = None
        if isinstance(node, MemDepNode | RegDepNode):
            cs_instr = self._instructions.get(node.ins_addr, None)
            instr = cs_instr.insn if cs_instr else None
        return GraphBox(node, node_lines(node, instr), 0, node_style(node))

    def edge_styles(self) -> None:
        """Give the edges on the traced path, and the ancestor edges, their styles."""
        ref = self._ddg
        for edge in self.graph.picture.edges:
            src, dst = edge.src.node, edge.dst.node
            data = ref.get_edge_data(src, dst) if ref is not None else None
            if dst in self.traced_ancestors or src in self.traced_descendants:
                edge.style = TRACED_EDGE_STYLE
            elif data and data.get("label") == "ancestor":
                edge.style = ANCESTOR_EDGE_STYLE
            else:
                edge.style = ""

    #
    # Tracing
    #

    def trace(self, node: BaseDepNode | None) -> None:
        """Highlight the paths to ``node`` (or from it, with :attr:`trace_descendants`); None clears them."""
        self.traced_ancestors = set()
        self.traced_descendants = set()
        if node is not None and self._ddg is not None and node in self._ddg:
            if self.trace_descendants:
                self.traced_descendants = descendants(self._ddg, node)
            else:
                self.traced_ancestors = ancestors(self._ddg, node)
        if self.on_traced is not None:
            self.on_traced()

    def toggle_trace_direction(self) -> None:
        self.trace_descendants = not self.trace_descendants
        self.trace(self.graph.selected)

    def activate(self, node: BaseDepNode) -> None:
        """A double click: show the node's instruction."""
        if node.ins_addr:
            self.workspace.viz(node.ins_addr)

    #
    # The graphs
    #

    def use_subgraph(self, node: BaseDepNode, backwards: bool) -> None:
        """Show only what ``node`` depends on (``backwards``) or what depends on it."""
        self._ddg = self._data_dep.get_data_dep(node, graph_has_tmp_nodes(self._ddg), backwards)
        self.reload()

    def toggle_graph(self) -> None:
        """Switch between the full graph and the one without temporaries, or leave a traced node's graph."""
        if self._data_dep is None:
            return
        if self._ddg is self._data_dep.simplified_graph:
            self._ddg = self._data_dep.graph
        elif self._ddg is self._data_dep.sub_graph:
            self._ddg = self._data_dep.graph if graph_has_tmp_nodes(self._ddg) else self._data_dep.simplified_graph
        else:
            self._ddg = self._data_dep.simplified_graph
        self.reload()

    def toggle_text(self) -> str:
        if self._data_dep is not None and self._ddg is self._data_dep.graph:
            return "Hide temp nodes"
        if self._data_dep is not None and self._ddg is self._data_dep.simplified_graph:
            return "Show temp nodes"
        return "Untrack node"

    def context_menu(self, node: BaseDepNode | None = None) -> Menu | None:
        """A node's menu (trace backward or forward), or, off the nodes, the view's options."""
        if node is not None:
            return Menu(
                "",
                [
                    MenuEntry("Trace backward", lambda: self.use_subgraph(node, True)),
                    MenuEntry("Trace forward", lambda: self.use_subgraph(node, False)),
                ],
            )
        if self._data_dep is None:
            return None
        return Menu("Options", [MenuEntry(self.toggle_text(), self.toggle_graph)])

    #
    # Search
    #

    def search_next(self, name: str, value: str, address: str) -> Any:
        """
        Select the next node matching the criteria (from the first when the criteria changed); returns it, or None
        with :attr:`search` ``.error`` set.
        """
        search = self.search
        if (name, value, address) != (search.name, search.value, search.address) or not search.matches:
            search.name, search.value, search.address = name, value, address
            nodes = self._ddg.nodes if self._ddg is not None else []
            search.matches, search.error = search_nodes(nodes, name, value, address)
            search.index = -1
        if not search.matches:
            return None
        search.index = (search.index + 1) % len(search.matches)
        node = search.matches[search.index]
        self.graph.selected = node
        return node


__all__ = [
    "DataDepPresenter",
    "NodeSearch",
    "ancestors",
    "data_dep_keymap",
    "descendants",
    "graph_has_tmp_nodes",
    "instruction_map",
    "instruction_text",
    "node_lines",
    "node_style",
    "node_tooltip",
    "search_nodes",
]
