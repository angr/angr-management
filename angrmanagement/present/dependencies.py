"""
The dependency view without a toolkit.

The dependency analysis (it needs operation-mango's ``argument_resolver``; without it the job says so and the view
stays empty, as in Qt) hands the view a sink, the instruction of the sink, and the transitive closures of the
definitions that reach it. :func:`dependency_graph` makes the tree the view shows, with the sink as its only root,
and :func:`definition_lines` gives each node's two lines: what is defined, and the instruction that defines it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import networkx
from angr import SIM_PROCEDURES
from angr.code_location import ExternalCodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register

from angrmanagement.utils import get_string_for_display, locate_function

from .base import InstancePresenter, project_of
from .graphs import GraphBox, TreeGraphPresenter
from .spans import Line

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.key_definitions.atoms import Atom
    from angr.knowledge_plugins.key_definitions.definition import Definition

    from angrmanagement.data.instance import Instance

#: The colours of the Qt dependency blocks: the definition dark blue, the instruction black, a string grey.
DEFINITION_STYLE = "dependency.definition"
INSTRUCTION_STYLE = "dependency.instruction"
TEXT_STYLE = "dependency.text"


def function_offset_text(instance: Instance, addr: int | None) -> str:
    """
    Where ``addr`` is: ``function+offset`` (the function's address when it has no name), a SimProcedure's name, or
    ``Unknown``.
    """
    if addr is None:
        return "Unknown"
    the_func = locate_function(instance, addr)
    project = project_of(instance)
    if the_func is None:
        # is it a SimProcedure?
        if project is not None and project.is_hooked(addr):
            hooker = project.hooked_by(addr)
            return "SimProcedure " + hooker.__class__.__name__.split(".")[-1]
        return "Unknown"
    offset = addr - the_func.addr
    return f"{the_func.name}{offset:+x}" if the_func.name else f"{the_func.addr:#x}{offset:+x}"


def atom_text(instance: Instance, atom: Any, addr: int | None) -> str:
    """What a definition defines: a register, a stack slot or a memory address, with where it is defined."""
    addr_str = "unknown address" if addr is None else f"{addr:#x}"
    if isinstance(atom, Register):
        project = project_of(instance)
        assert project is not None
        register_name = project.arch.translate_register_name(atom.reg_offset, size=atom.size)
        return f"Register {register_name} @ {addr_str}"
    if isinstance(atom, MemoryLocation):
        if isinstance(atom.addr, SpOffset):
            return f"Stack sp{atom.addr.offset:+#x} @ {addr_str}"
        if isinstance(atom.addr, int):
            return f"Memory {atom.addr:#x} @ {addr_str}"
    return ""


@dataclass(eq=False)
class DependencyNode:
    """A node of the tree: a definition, or (for the sink) an atom, and the address of its instruction."""

    definition: Definition | None = None
    atom: Atom | None = None
    addr: int | None = None


def definition_lines(instance: Instance, node: DependencyNode) -> list[Line]:
    """
    A node's two lines as the Qt block shows them: what it defines (``Register rdi @ 0x400...``), then the function,
    the instruction and, if the instruction refers to one, a string.
    """
    atom = node.definition.atom if node.definition is not None else node.atom
    definition = atom_text(instance, atom, node.addr)
    if not definition:
        # fallback
        definition = repr(node.definition.atom) if node.definition is not None else repr(atom)
    second = Line()
    if node.addr is None:
        second.append("Unknown", INSTRUCTION_STYLE)
    else:
        function = function_offset_text(instance, node.addr)
        second.append(f"{function}:  {instance.get_instruction_text_at(node.addr)}", INSTRUCTION_STYLE)
        project: Any = instance.project
        text = get_string_for_display(instance.cfg, node.addr, project, max_size=60)
        if text:
            second.append("  ").append(text, TEXT_STYLE)
    return [Line().append(definition, DEFINITION_STYLE), second]


def is_shown(project, definition: Definition) -> bool:
    """Whether the tree shows ``definition``: not one outside the binary, nor one in an unresolvable-target stub."""
    if isinstance(definition.codeloc, ExternalCodeLocation):
        return False
    if project.is_hooked(definition.codeloc.block_addr):
        hook = project.hooked_by(definition.codeloc.block_addr)
        stubs = SIM_PROCEDURES["stubs"]
        if isinstance(hook, stubs["UnresolvableJumpTarget"] | stubs["UnresolvableCallTarget"]):
            return False
    return True


def dependency_graph(
    project, closures: dict[Any, networkx.DiGraph], sink_atom: Any, sink_addr: int | None
) -> tuple[networkx.DiGraph, DependencyNode]:
    """
    The tree of the closures with the sink (the atom at ``sink_addr``) as its only root: every definition the
    closures end in points at it. Returns the graph and the sink's node.
    """
    g = networkx.DiGraph()
    source_node = DependencyNode(atom=sink_atom, addr=sink_addr)
    g.add_node(source_node)
    all_graphs = networkx.compose_all(closures.values())
    converted: dict[Any, DependencyNode | None] = {}

    def convert(definition) -> DependencyNode | None:
        if definition not in converted:
            node = DependencyNode(definition=definition, addr=definition.codeloc.ins_addr)
            converted[definition] = node if is_shown(project, definition) else None
        return converted[definition]

    for node_ in all_graphs.nodes:
        node = convert(node_)
        if node is not None:
            g.add_node(node)
        # this is a hack - we only want our sink as the only root of the dependency tree (a definition the tree
        # leaves out has no node; the Qt view added an edge from None, which networkx refuses)
        if node is not None and all_graphs.out_degree[node_] == 0:
            g.add_edge(node, source_node)

    for src_, dst_ in all_graphs.edges:
        src = convert(src_)
        dst = convert(dst_)
        if src is not None and dst is not None:
            g.add_edge(src, dst)
    return g, source_node


class DependencyPresenter(InstancePresenter):
    """The dependency view: the job sets :attr:`sink_atom`, :attr:`sink_ins_addr` and :attr:`closures`, then reloads."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        super().__init__(workspace, "dependencies", instance, default_docking_position)
        self.base_caption = "Dependencies"
        self.sink_atom: Atom | None = None
        self.sink_ins_addr: int | None = None
        self.closures: dict[Definition, networkx.DiGraph] | None = None
        self._graph: networkx.DiGraph | None = None
        self.graph = TreeGraphPresenter(lambda: self._graph, self._box, "tree")
        #: called after the graph changed
        self.on_reloaded: Callable[[], None] | None = None

    def reload(self) -> None:
        project = project_of(self.instance)
        if not self.closures or project is None:
            self._graph = None
        else:
            self._graph, _sink = dependency_graph(project, self.closures, self.sink_atom, self.sink_ins_addr)
        self.graph.invalidate()
        if self.on_reloaded is not None:
            self.on_reloaded()

    def _box(self, node: DependencyNode) -> GraphBox:
        return GraphBox(node, definition_lines(self.instance, node), node.addr or 0)

    def activate(self, node: DependencyNode) -> None:
        """A double click: show the node's instruction."""
        self.workspace.viz(node.addr)


__all__ = [
    "DependencyNode",
    "DependencyPresenter",
    "atom_text",
    "definition_lines",
    "dependency_graph",
    "function_offset_text",
    "is_shown",
]
