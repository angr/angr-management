"""
The proximity view without a toolkit.

The view shows a function's proximity graph (angr's Proximity analysis over its decompilation): the function, its
calls with their arguments, and the strings and values they use, in call order. A call can be expanded into the
graph of its callee, and an expanded function collapsed again. :func:`proximity_line` gives each node's text, coloured
as the Qt blocks colour it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr.analyses.proximity_graph import (
    BaseProxiNode,
    CallProxiNode,
    FunctionProxiNode,
    IntegerProxiNode,
    StringProxiNode,
    UnknownProxiNode,
    VariableProxiNode,
)

from .base import InstancePresenter, project_of
from .graphs import PROXIMITY_CELL_MARGINS, GraphBox, TreeGraphPresenter
from .keymap import Binding, Keymap
from .spans import Line

if TYPE_CHECKING:
    from collections.abc import Callable

    import networkx
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance

#: The colour entries of the kinds of argument.
ARGUMENT_STYLES = {
    StringProxiNode: "proximity_string_node_text_color",
    IntegerProxiNode: "proximity_integer_node_text_color",
    VariableProxiNode: "proximity_variable_node_text_color",
    UnknownProxiNode: "proximity_unknown_node_text_color",
}
CALL_STYLE = "proximity_call_node_text_color"
#: The background of the blocks, as the Qt proximity blocks paint them.
NODE_STYLE = "graph.node bg:proximity_node_background_color"


def argument_text(arg: Any) -> tuple[type, str]:
    """A call argument's kind and its text in the call's block."""
    if isinstance(arg, StringProxiNode):
        return StringProxiNode, '"' + arg.content.decode("utf-8").replace("\n", "\\n") + '"'
    if isinstance(arg, IntegerProxiNode):
        return IntegerProxiNode, str(arg.value)
    if isinstance(arg, VariableProxiNode):
        return VariableProxiNode, str(arg.name)
    if isinstance(arg, UnknownProxiNode):
        return UnknownProxiNode, str(arg.dummy_value)
    return object, "Unknown"


def function_node_name(instance: Instance, func_node: Any) -> str:
    """The name a function node shows: the knowledge base's name, the analysis' or the address."""
    kb = instance.kb
    func = kb.functions.get(func_node.addr) if kb is not None else None
    return func.name if func is not None else (func_node.func_name or hex(func_node.addr))


def call_style(func: Function | None) -> str:
    """The colour entry of a call to ``func``: SimProcedures and PLT stubs have their own."""
    if func is not None and func.is_simprocedure:
        return "proximity_call_node_text_color_simproc"
    if func is not None and func.is_plt:
        return "proximity_call_node_text_color_plt"
    return CALL_STYLE


def proximity_line(instance: Instance, node: BaseProxiNode) -> Line:
    """The text of a proximity node's block, in the colours of the Qt blocks."""
    line = Line()
    if isinstance(node, FunctionProxiNode):
        return line.append(f"Function {function_node_name(instance, node.func)}", "proximity_function_node_text_color")
    if isinstance(node, StringProxiNode):
        return line.append('"' + node.content.decode("utf-8") + '"', "proximity_string_node_text_color")
    if isinstance(node, CallProxiNode):
        kb = instance.kb
        func = kb.functions.get(node.callee.addr) if kb is not None else None
        name = func.name if func is not None else node.callee.func_name
        style = call_style(func)
        line.append(str(name), style).append("(", style)
        args = [argument_text(arg) for arg in node.args] if node.args is not None else []
        for idx, (kind, text) in enumerate(args):
            line.append(text, ARGUMENT_STYLES.get(kind, CALL_STYLE))
            if idx != len(args) - 1:
                line.append(", ", style)
        return line.append(")", style)
    # variables and other nodes draw an empty block in Qt
    return line


def node_addr(node: BaseProxiNode) -> int:
    """The address GraphLayouter orders a proximity node by."""
    if isinstance(node, (StringProxiNode, VariableProxiNode)):
        return node.addr
    if isinstance(node, FunctionProxiNode):
        return node.func.addr
    return 0


def sort_by_reference(boxes: list[GraphBox]) -> list[GraphBox]:
    """Order a row of blocks by the address of each node's first reference, as the Qt proximity graph does."""
    return sorted(boxes, key=lambda b: next(iter(b.node.ref_at)) if b.node.ref_at else 0)


def proximity_keymap() -> Keymap:
    """The proximity view's keys: Tab and Ctrl+double-click's expand and collapse, which a terminal gets as keys."""
    return Keymap(
        "proximity",
        [
            Binding("Tab", "go_to_disassembly", "Show the selected block's reference in the disassembly"),
            Binding("+", "expand_selected", "Expand the selected call into its callee (Ctrl+double-click)"),
            Binding("-", "collapse_selected", "Collapse the selected function (Ctrl+double-click)"),
        ],
    )


class ProximityPresenter(InstancePresenter):
    """The proximity view of :attr:`function`; setting the function runs the analysis, as in Qt."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "proximity", instance, default_docking_position)
        self.base_caption = "Proximity"
        self._function: Function | None = None
        self._expand_function_addrs: set[int] = set()
        self._proximity_graph: networkx.DiGraph | None = None
        self.graph = TreeGraphPresenter(
            self._graph_source, self._box, "graph", node_sorter=sort_by_reference, margins=PROXIMITY_CELL_MARGINS
        )
        #: called after the graph changed
        self.on_reloaded: Callable[[], None] | None = None

    @property
    def keymap(self) -> Keymap:
        return proximity_keymap()

    @property
    def function(self) -> Function | None:
        return self._function

    @function.setter
    def function(self, v: Function | None) -> None:
        if v is not None and v is not self._function:
            self._function = v
            self._expand_function_addrs.clear()
            self.run_analysis()

    @property
    def proximity_graph(self) -> networkx.DiGraph | None:
        return self._proximity_graph

    def get_decompilation(self):
        project = project_of(self.instance)
        assert project is not None and self._function is not None
        cfg: Any = self.instance.cfg
        return project.analyses.Decompiler(self._function, cfg=cfg, use_cache=True)

    def run_analysis(self) -> None:
        project = project_of(self.instance)
        if project is None or self._function is None:
            return
        dec = self.get_decompilation()
        inst = self.instance
        prox = project.analyses.Proximity(
            self._function,
            inst.cfg,
            inst.kb.xrefs,  # type: ignore[union-attr]
            decompilation=dec,
            expand_funcs=self._expand_function_addrs,
        )
        self._proximity_graph = prox.graph
        self.reload()

    def reload(self) -> None:
        self.graph.invalidate()
        if self.on_reloaded is not None:
            self.on_reloaded()

    def clear(self) -> None:
        self._proximity_graph = None
        self.reload()

    def expand_function(self, func) -> None:
        if func.addr not in self._expand_function_addrs:
            self._expand_function_addrs.add(func.addr)
            # re-run the analysis
            self.run_analysis()

    def collapse_function(self, func) -> None:
        if func.addr in self._expand_function_addrs:
            self._expand_function_addrs.discard(func.addr)
            # re-run the analysis
            self.run_analysis()

    def _graph_source(self) -> networkx.DiGraph | None:
        return self._proximity_graph or None

    def _box(self, node: BaseProxiNode) -> GraphBox:
        return GraphBox(node, [proximity_line(self.instance, node)], node_addr(node), NODE_STYLE)

    #
    # Actions on blocks
    #

    def activate(self, node: BaseProxiNode) -> None:
        """A double click: show the node's first reference."""
        if node.ref_at:
            self.workspace.viz(next(iter(node.ref_at)))

    def expand_selected(self) -> None:
        node = self.graph.selected
        if isinstance(node, CallProxiNode):
            self.expand_function(node.callee)

    def collapse_selected(self) -> None:
        node = self.graph.selected
        if isinstance(node, FunctionProxiNode):
            self.collapse_function(node.func)

    def go_to_disassembly(self) -> None:
        """Show the selected block's first reference, or the function, in the disassembly."""
        node = self.graph.selected
        if node is not None and node.ref_at:
            addr = next(iter(node.ref_at))
        elif self._function is not None:
            addr = self._function.addr
        else:
            return
        self.workspace.jump_to(addr)


__all__ = [
    "ProximityPresenter",
    "argument_text",
    "call_style",
    "function_node_name",
    "node_addr",
    "proximity_keymap",
    "proximity_line",
    "sort_by_reference",
]
