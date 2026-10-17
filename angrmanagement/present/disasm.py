"""
The disassembly view without a toolkit.

:class:`DisasmPresenter` holds what both frontends' disassembly views share: the selection (:class:`InfoDock`), the
jump history, the function shown, the disassembly level (machine code, lifter IR or AIL), the display options, graph
versus linear mode, the find bar's matches, the context menus, the key bindings and the palette commands. The
frontend's view widget owns a presenter and gives it two *controls*, ``view.flow_graph`` and ``view.linear_viewer``,
which draw the graph and the linear listing and answer the presenter's calls (``show_instruction``, ``refresh``,
``reload``, ``redraw``, ``set_disassembly_level``, ``navigate_to_addr``, ...). The Qt view's controls are
``QDisassemblyGraph`` and ``QLinearDisassembly``; the terminal's are its graph and linear widgets.

A view may implement any ``popup_*`` method itself (the Qt view opens its dialogs); otherwise the presenter asks
through :mod:`angrmanagement.logic.ui_services` prompts.

Render models for frontends that lay text out in cells: :meth:`DisasmPresenter.graph_doc` turns a function graph
into a :class:`GraphDoc` (a :class:`BlockDoc` of styled lines per block, the block positions and the routed edges, in
the frontend's units), and :class:`LinearSource` walks the CFB blanket for the linear view.
"""

from __future__ import annotations

import bisect
import contextlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from angr.analyses.cfg.cfb import MemoryRegion, Unknown
from angr.analyses.decompiler.utils import to_ail_supergraph
from angr.block import Block
from angr.knowledge_plugins.cfg import MemoryData
from archinfo.arch_arm import get_real_address_if_arm, is_arm_arch
from sortedcontainers import SortedDict

from angrmanagement.config import Conf
from angrmanagement.data.annotations import CommentKind
from angrmanagement.data.function_graph import FunctionGraph
from angrmanagement.data.highlight_region import SynchronizedHighlightRegion
from angrmanagement.data.object_container import ObjectContainer
from angrmanagement.data.search import BytePattern, Searcher, SearchError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.commands import ViewCommand
from angrmanagement.logic.disassembly import InfoDock, JumpHistory
from angrmanagement.logic.signal import Signal
from angrmanagement.logic.threads import gui_thread_schedule_async, needs_gui_thread
from angrmanagement.plugins.base_plugin import to_color
from angrmanagement.utils import get_label_text, get_out_branches, locate_function
from angrmanagement.utils.cache import SmartLRUCache
from angrmanagement.utils.cfg import categorize_edges
from angrmanagement.utils.graph import get_out_branches as function_out_branches
from angrmanagement.utils.graph_layouter import GraphLayouter

from .base import FunctionPresenter, Synchronized, ask_text, container
from .block_tree import BlockTreeNodeOptions, QVariableObj
from .block_tree.disasm_nodes import (
    AlignmentNode,
    DisasmNode,
    InsnNode,
    LabelNode,
    MemoryDataNode,
    UnknownNode,
    build_block_nodes,
)
from .dialogs import (
    PatchAssembler,
    address_of_text,
    depends_on_form,
    func_doc_form,
    func_doc_target,
    hook_form,
    jump_to_form,
    label_name,
    rename_label_form,
    set_comment_form,
)
from .disasm_menus import DisasmInsnContextMenu, DisasmLabelContextMenu, DisasmOptionsMenu, DisasmUnknownContextMenu
from .disasm_style import BLOCK_STYLE, block_background, insn_background
from .forms import ask_form
from .keymap import Binding, Keymap
from .marks import Mark, sorted_marks
from .menus import Menu, MenuEntry, MenuSeparator
from .spans import Line, Span
from .theme import BACKGROUND_PREFIX

if TYPE_CHECKING:
    import re
    from collections.abc import Callable

    from angr.knowledge_plugins import VariableManager
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.disassembly.info_dock import OperandDescriptor

_l = logging.getLogger(__name__)

# the minimum interval (in seconds) between two viewport refreshes triggered by incremental CFB object additions
# during CFG recovery
MIN_OBJECTS_ADDED_REFRESH_INTERVAL = 0.25


class DisassemblyLevel(Enum):
    """What the disassembly view shows of each instruction."""

    MachineCode = 0
    LifterIR = 1
    AIL = 2


#: The names of the levels, as the level selector shows them.
LEVEL_NAMES = {
    DisassemblyLevel.MachineCode: "Machine Code",
    DisassemblyLevel.LifterIR: "Lifter IR",
    DisassemblyLevel.AIL: "AIL",
}

#: The disassembly view's palette commands: caption and the presenter method each runs.
DISASM_COMMANDS: list[tuple[str, str]] = [
    ("Comment", "begin_inline_comment"),
    ("Comment (multi-line)...", "popup_comment_dialog"),
    ("Comment: Set as function comment", "set_function_comment"),
    ("Comment: Toggle repeatable", "toggle_repeatable_comment"),
    ("Toggle Bookmark", "toggle_bookmark_at_selection"),
    ("Jump Back", "jump_back"),
    ("Jump Forward", "jump_forward"),
    ("Jump To", "popup_jumpto_dialog"),
    ("Toggle Addresses", "toggle_show_address"),
    ("Toggle Exception Edges", "toggle_show_exception_edges"),
    ("Toggle Graph/Linear view", "toggle_disasm_view"),
    ("Toggle Minimap", "toggle_show_minimap"),
    ("Toggle Smart Highlighting", "toggle_smart_highlighting"),
    ("Toggle Variable Identifiers", "toggle_show_variable_identifier"),
    ("Toggle Variables", "toggle_show_variable"),
    ("Find", "show_find_bar"),
    ("Find Next", "find_next"),
    ("Find Previous", "find_previous"),
    ("View AIL", "set_disassembly_level_ail"),
    ("View Lifter IR", "set_disassembly_level_lifter_ir"),
    ("View Machine Code", "set_disassembly_level_machine_code"),
]


def disassembly_keymap() -> Keymap:
    """
    The disassembly view's keys: DisassemblyView.keyPressEvent, QDisassemblyBaseControl.keyPressEvent, the find
    shortcuts and the zoom keys of the graph. The terminal has no zoom; Ctrl+= and Ctrl+- step through its levels of
    detail instead.
    """
    return Keymap(
        "disassembly",
        [
            Binding("G", "popup_jumpto_dialog", "Jump to an address or a function"),
            Binding("Alt+Left", "jump_back", "Jump back", 2, "Ctrl+Left"),
            Binding("Alt+Right", "jump_forward", "Jump forward", 2, "Ctrl+Right"),
            Binding("Esc", "jump_back", "Jump back"),
            Binding("A", "toggle_smart_highlighting", "Toggle smart highlighting"),
            Binding("Tab", "decompile_current_function", "Decompile the function"),
            Binding(";", "begin_inline_comment", "Comment"),
            Binding("Ctrl+/", "popup_comment_dialog", "Comment (multi-line)"),
            Binding("Ctrl+;", "popup_comment_dialog", "Comment (multi-line)", 2),
            Binding("Space", "toggle_disasm_view", "Toggle graph and linear view"),
            Binding("C", "define_code", "Define code at the selected label"),
            Binding("U", "undefine_code", "Undefine the selected instruction"),
            Binding("N", "popup_rename_label_dialog", "Rename the label"),
            Binding("X", "xrefs", "Cross-references"),
            Binding("Ctrl+F", "show_find_bar", "Find"),
            Binding("F3", "find_next", "Find next"),
            Binding("Shift+F3", "find_previous", "Find previous", 2, "Shift+N"),
            Binding("Ctrl+=", "more_detail", "Zoom in (more detail)"),
            Binding("Ctrl+-", "less_detail", "Zoom out (less detail)"),
            Binding("Ctrl+0", "reset_detail", "Reset the zoom"),
            Binding("Shift+F10", "context_menu", "Context menu"),
            Binding("Return", "activate", "Follow the selected operand"),
        ],
    )


def register_disasm_commands(workspace, view_class: type | None = None) -> None:
    """
    Register the disassembly view's palette commands. They run on the focused view's presenter, which forwards to the
    view whatever the view does itself (dialogs).
    """
    if view_class is None:
        view_class = DisasmPresenter
    workspace.command_manager.register_commands(
        [
            ViewCommand(
                "disassembly_view_" + method,
                "Disassembly: " + caption,
                getattr(view_class, method),
                view_class,
                workspace,
            )
            for caption, method in DISASM_COMMANDS
        ]
    )


#
# Render models
#


@dataclass
class BlockDoc:
    """
    One graph block as lines of styled text.

    :param addr:        The block's address.
    :param lines:       Its lines, top to bottom.
    :param nodes:       The node each line belongs to (same length as ``lines``).
    :param header:      What a collapsed block shows: its label.
    """

    addr: int
    lines: list[Line]
    nodes: list[DisasmNode]
    header: str = ""
    idx: int | None = None

    @property
    def width(self) -> int:
        return max((line.width for line in self.lines), default=0)

    @property
    def height(self) -> int:
        return len(self.lines)

    def rows_of(self, addr: int) -> list[int]:
        """The rows of the instruction or label at ``addr``."""
        return [row for row, node in enumerate(self.nodes) if getattr(node, "addr", None) == addr]

    @property
    def insn_addrs(self) -> list[int]:
        return [node.addr for node in self.nodes if isinstance(node, InsnNode)]


@dataclass
class EdgeRoute:
    """An edge as the layouter routed it: corner points from the source's bottom to above the destination."""

    points: list[tuple[int, int]]
    sort: int | None
    src_addr: int
    dst_addr: int


@dataclass
class GraphDoc:
    """
    A function's graph as blocks of text, their positions and the routed edges, in the frontend's units.

    ``blocks`` and ``layout`` are keyed by the supergraph node.
    """

    blocks: dict[Any, BlockDoc] = field(default_factory=dict)
    layout: dict[Any, tuple[int, int]] = field(default_factory=dict)
    sizes: dict[Any, tuple[int, int]] = field(default_factory=dict)
    edges: list[EdgeRoute] = field(default_factory=list)
    entry: Any = None
    insn_block: dict[int, Any] = field(default_factory=dict)
    #: the supergraph laid out
    graph: Any = None

    @property
    def size(self) -> tuple[int, int]:
        """The width and height that hold every block and edge."""
        width = height = 0
        for key, (x, y) in self.layout.items():
            w, h = self.sizes[key]
            width, height = max(width, x + w), max(height, y + h)
        for edge in self.edges:
            for x, y in edge.points:
                width, height = max(width, x + 1), max(height, y + 1)
        return width, height


def cell_size(block: BlockDoc) -> tuple[int, int]:
    """A block's size in cells: its widest line and a border and a space each side, its lines and two borders."""
    return block.width + 4, block.height + 2


#: The margins the terminal frontend lays a graph out with, in cells.
CELL_MARGINS = {"x_margin": 2, "y_margin": 1, "row_margin": 1, "col_margin": 2, "min_edge_col_width": 4, "arrow_gap": 1}


class LinearSource:
    """
    The linear view's walk over the CFB blanket, without drawing anything.

    The listing is addressed by a byte *offset* into the concatenated memory regions (TLS and kernel regions are
    skipped), as the Qt linear view's scroll bar is. :meth:`objects_at` returns the objects to show from an offset,
    each as a list of lines from its node, which :meth:`node_for` makes (and caches, as the Qt view caches its items).

    :param presenter:   The disassembly presenter: instance, level, options, and the disassembly caches.
    """

    def __init__(self, presenter: DisasmPresenter, cache_size: int = 1024) -> None:
        self.presenter = presenter
        self.offset_to_region: SortedDict = SortedDict()
        self.addr_to_region_offset: SortedDict = SortedDict()
        self.max_offset = 0
        self.objects: SmartLRUCache = SmartLRUCache(maxsize=cache_size)
        self.initialize()

    @property
    def instance(self) -> Instance:
        return self.presenter.instance

    @property
    def cfb(self) -> Any:
        """The instance's CFB container."""
        return self.instance.cfb

    def initialize(self) -> None:
        """Enumerate the memory regions again and forget every cached object (QLinearDisassembly.initialize)."""
        self.objects.clear()
        self.addr_to_region_offset.clear()
        self.offset_to_region.clear()
        self.presenter.clear_linear_disasm_cache()
        self.max_offset = 0
        if self.cfb.am_none:
            return
        byte_offset = 0
        mr: MemoryRegion
        for mr in self.cfb.regions:
            if mr.type in {"tls", "kernel"}:
                # Skip TLS objects and kernel objects
                continue
            self.addr_to_region_offset[mr.addr] = byte_offset
            self.offset_to_region[byte_offset] = mr
            byte_offset += mr.size
        self.max_offset = byte_offset

    def offset_of_addr(self, addr: int) -> int | None:
        """The offset that shows ``addr`` at the top (QLinearDisassembly.navigate_to_addr)."""
        if not self.addr_to_region_offset:
            return None
        try:
            floor_region_addr = next(self.addr_to_region_offset.irange(maximum=addr, reverse=True))
        except StopIteration:
            floor_region_addr = next(self.addr_to_region_offset.irange())
        return self.addr_to_region_offset[floor_region_addr] + addr - floor_region_addr

    def region_from_offset(self, offset: int) -> tuple[Any, Any]:
        try:
            off = next(self.offset_to_region.irange(maximum=offset, reverse=True))
            return off, self.offset_to_region[off]
        except StopIteration:
            return None, None

    def region_from_addr(self, addr: int) -> tuple[Any, Any]:
        try:
            addr = next(self.addr_to_region_offset.irange(maximum=addr, reverse=True))
            off = self.addr_to_region_offset[addr]
            return off, self.offset_to_region[off]
        except StopIteration:
            return None, None

    def addr_of_offset(self, offset: int) -> int | None:
        base_offset, mr = self.region_from_offset(offset)
        if mr is None:
            return None
        return mr.addr + (offset - base_offset)

    def visible_addr_range(self, offset: int | None, rows: int) -> tuple[int, int] | None:
        """A cheap superset of the addresses ``rows`` lines from ``offset`` show (16 bytes a line at most)."""
        if offset is None:
            return None
        start = self.addr_of_offset(offset)
        if start is None:
            return None
        return start, start + max(rows, 1) * 16

    def _validate_cached(self, obj, node) -> bool:
        if isinstance(obj, Block) and isinstance(node, AlignmentNode):
            return node.size == obj.size
        if isinstance(obj, Block) and isinstance(node, LinearBlock):
            if node.level is not self.presenter.disassembly_level:
                return False
            return set(obj.instruction_addrs) == set(node.insn_addrs)
        if isinstance(obj, MemoryData) and isinstance(node, MemoryDataNode):
            return node.memory_data.size == obj.size
        if isinstance(obj, Unknown) and isinstance(node, UnknownNode):
            return node.bytes == obj.bytes
        return False

    def node_for(self, obj_addr: int, obj) -> Any:
        """
        The display object of a CFB object (QLinearDisassembly._obj_to_paintable): a :class:`LinearBlock` for a block
        of a function, an AlignmentNode, MemoryDataNode or UnknownNode, or None.
        """
        cached = self.objects.get(obj_addr)
        if cached is not None and self._validate_cached(obj, cached):
            return cached
        if cached is not None:
            del self.objects[obj_addr]
        node = self._make_node(obj_addr, obj)
        if node is not None:
            self.objects[obj_addr] = node
        return node

    def _make_node(self, obj_addr: int, obj) -> Any:
        presenter = self.presenter
        instance: Any = self.instance
        if isinstance(obj, Block):
            cfg = instance.cfg
            if isinstance(cfg, ObjectContainer) and cfg.am_none:
                return UnknownNode(obj_addr, obj.bytes)
            cfg_node = cfg.get_any_node(obj_addr, force_fastpath=True)
            if cfg_node is None:
                _l.warning("Failed to get a CFG node for address %#x.", obj_addr)
                return None
            func_addr = cfg_node.function_address
            if not instance.kb.functions.contains_addr(func_addr):
                _l.warning("Function %s does not exist, and we cannot get disassembly for block %s.", func_addr, obj)
                return None
            func = instance.kb.functions[func_addr]
            if func.is_alignment:
                return AlignmentNode(obj_addr, obj.size)
            disasm = presenter.linear_disasm(func)
            if presenter.disassembly_level is DisassemblyLevel.AIL:
                ail_obj = None
                if disasm.graph is not None:
                    for n in disasm.graph.nodes:
                        if n.addr == obj.addr:
                            ail_obj = n
                if ail_obj is None:
                    return None
                return LinearBlock(presenter, func_addr, disasm, obj.addr, [ail_obj], None)
            out_branches = function_out_branches(func, obj_addr)
            return LinearBlock(presenter, func_addr, disasm, obj.addr, [obj], out_branches)
        if isinstance(obj, MemoryData):
            return MemoryDataNode(instance, presenter.infodock, obj_addr, obj)
        if isinstance(obj, Unknown):
            return UnknownNode(obj_addr, obj.bytes)
        return None

    def lines_of(self, node: Any) -> list[Line]:
        if isinstance(node, LinearBlock):
            return node.lines()
        return node.lines(self.presenter, linear=True)

    def objects_at(
        self, offset: int, max_lines: int, start_line: int = 0
    ) -> tuple[list[tuple[int, Any, int]], int, int]:
        """
        The objects from ``offset`` on, skipping ``start_line`` lines of the first, until ``max_lines`` lines are
        filled (QLinearDisassembly._prepare_objects without the scene).

        :returns:   ``([(addr, node, first line shown), ...], offset, start line)``, with the offset and start line
                    moved to the first object that shows.
        """
        if self.cfb.am_none or not self.offset_to_region:
            return [], offset, start_line
        base_offset, mr = self.region_from_offset(offset)
        if mr is None:
            return [], offset, start_line
        addr = mr.addr + (offset - base_offset)

        if start_line < 0:
            # walk backwards until there are enough lines above
            try:
                top_obj_addr = self.cfb.floor_addr(addr=addr)
            except KeyError:
                top_obj_addr = addr
            for obj_addr, obj in self.cfb.ceiling_items(addr=top_obj_addr, reverse=True):
                if obj_addr >= top_obj_addr:
                    continue
                node = self.node_for(obj_addr, obj)
                if node is None:
                    continue
                start_line += len(self.lines_of(node))
                if start_line >= 0:
                    addr = obj_addr
                    new_region_addr = next(self.addr_to_region_offset.irange(maximum=addr, reverse=True), None)
                    if new_region_addr is None:
                        break
                    offset = (addr - new_region_addr) + self.addr_to_region_offset[new_region_addr]
                    break
            else:
                start_line = 0
                addr = next(self.addr_to_region_offset.irange())
                offset = self.addr_to_region_offset[addr]

        shown: list[tuple[int, Any, int]] = []
        lines = 0
        first_start = 0
        for obj_addr, obj in self.cfb.floor_items(addr=addr):
            obj_size = 0 if obj.size is None else obj.size
            if obj_addr + obj_size <= addr and (obj_size > 0 or obj_addr < addr):
                continue
            node = self.node_for(obj_addr, obj)
            if node is None:
                continue
            if obj_addr >= mr.addr + mr.size:
                base_offset, mr = self.region_from_addr(obj_addr)
                if mr is None:
                    break
            object_lines = len(self.lines_of(node))
            if start_line > 0 and start_line >= object_lines:
                start_line -= object_lines
                if obj_size == 0:
                    offset += 1
                elif obj_addr <= addr < obj_addr + obj_size:
                    offset += obj_addr + obj_size - addr
                else:
                    offset = base_offset + (obj_addr + obj_size - mr.addr)
                continue
            first = start_line if not shown else 0
            if not shown:
                first_start = start_line
            start_line = 0
            shown.append((obj_addr, node, first))
            lines += object_lines - first
            if lines > max_lines:
                break
        return shown, offset, first_start


class LinearBlock:
    """
    A block of the linear view as lines: the nodes of :func:`build_block_nodes`, laid out for the linear listing,
    and an empty line after it, as the Qt linear block leaves.
    """

    def __init__(self, presenter: DisasmPresenter, func_addr: Any, disasm, addr: int, cfg_nodes, out_branches):
        self.presenter = presenter
        self.func_addr = func_addr
        self.disasm = disasm
        self.addr = addr
        self.level = presenter.disassembly_level
        self.options = BlockTreeNodeOptions()
        self.options.show_variables = presenter.show_variable
        self.options.show_variable_identifiers = presenter.show_variable_identifier
        self.nodes = build_block_nodes(
            presenter.instance, func_addr, disasm, presenter.infodock, cfg_nodes, out_branches, self.options
        )

    @property
    def insn_addrs(self) -> list[int]:
        return [node.addr for node in self.nodes if isinstance(node, InsnNode)]

    def lines(self) -> list[Line]:
        return [line for _node, line in self.node_lines()]

    def node_lines(self) -> list[tuple[Any, Line]]:
        """Each line with the node it belongs to; the empty line at the end belongs to no node."""
        self.options.show_variables = self.presenter.show_variable
        self.options.show_variable_identifiers = self.presenter.show_variable_identifier
        out: list[tuple[Any, Line]] = []
        for node in self.nodes:
            for line in self.presenter.node_lines(node, linear=True):
                out.append((node, line))
        out.append((None, Line()))
        return out


#
# The presenter
#


class DisasmPresenter(Synchronized, FunctionPresenter):
    """
    The state and actions of a disassembly view.

    :param workspace:                   The workspace.
    :param instance:                    The instance whose disassembly is shown.
    :param default_docking_position:    Where the view docks.
    """

    FIND_HIGHLIGHT_LIMIT = 512
    FIND_MODE_TEXT = "Text"
    FIND_MODE_TEXT_INSN = "Text (instruction only)"
    FIND_MODE_BYTES = "Byte pattern"
    FIND_MODES = (FIND_MODE_TEXT, FIND_MODE_TEXT_INSN, FIND_MODE_BYTES)

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "center") -> None:
        FunctionPresenter.__init__(self, workspace, "disassembly", instance, default_docking_position)
        Synchronized.__init__(self)
        self.base_caption = "Disassembly"

        #: instructions a pattern or a discovered family covers, painted in their own color
        self.pattern_highlight_addrs: set[int] = set()
        self._disassembly_level = DisassemblyLevel.MachineCode
        self._show_minimap = True
        self._show_address = True
        self._show_variable = True
        # whether we want to show identifier or not
        self._show_variable_ident = False
        # whether we want to show exception edges and all nodes that are only reachable through exception edges
        self._show_exception_edges = True

        self._prefer_graph = True
        self._displaying_function = False
        self._current_view: Any = None
        self._last_objects_added_refresh = 0.0

        self.jump_history = JumpHistory()
        self.infodock = InfoDock(self)
        self._variable_recovery_flavor = "fast"
        self.variable_manager: VariableManager | None = None

        #: the instruction a context menu or a double click is about; it wins over the selection while it is set
        self.insn_addr_on_context_menu: int | None = None

        #: the find bar the view shows (a QFindBar, or the terminal's); it holds the query and shows the counter
        self.find_bar: Any = None
        self._find_matches: list[tuple[int, str]] = []
        self._find_data_matches: dict[int, int] = {}  # match addr -> owning data item addr
        self._find_matches_capped = False
        self._find_index = -1
        self._find_highlighted = False
        self._find_text_cache: dict[int, list[tuple[int, str, bytes]]] = {}
        self._in_find_refresh = False

        # the analyses shown, by function: the graph's and the linear view's (as each Qt control kept its own)
        self._graph_disasms = SmartLRUCache(maxsize=1024)
        self._graph_ail_disasms = SmartLRUCache(maxsize=1024)
        self._linear_disasms = SmartLRUCache(maxsize=1024)
        self._linear_ail_disasms = SmartLRUCache(maxsize=1024)

        #: emitted with the new level when the disassembly level changes
        self.level_changed = Signal()
        #: emitted when the view switches between graph and linear
        self.view_visibility_changed = Signal()

        self._events_registered = False
        self._view_overrides = True

    #
    # The frontend
    #

    def attach(self, view, node_target: Any = None) -> None:
        """
        Show this presenter in ``view``, and start listening to events. The display nodes call ``node_target`` for
        jumps and context menus: the view by default (the Qt view, whose menus are Qt's), or this presenter.
        """
        self.view = view
        self.infodock.disasm_view = node_target if node_target is not None else view
        # a view that hands the nodes to the presenter does everything through it; only one that takes the nodes
        # itself (the Qt view) overrides the presenter's prompts and menus with its own
        self._view_overrides = node_target is None
        self.register_events()

    @property
    def graph(self) -> Any:
        """The view's graph control."""
        return getattr(self.view, "flow_graph", None)

    @property
    def linear(self) -> Any:
        """The view's linear control."""
        return getattr(self.view, "linear_viewer", None)

    def _view_method(self, name: str) -> Callable | None:
        """The view's own implementation of ``name``, if it has one (the Qt view's dialogs)."""
        if self.view is None or self.view is self or not self._view_overrides:
            return None
        return getattr(self.view, name, None)

    def _show_control(self, control) -> None:
        show = getattr(self.view, "show_control", None)
        if show is not None:
            show(control)

    def _control_switched(self, control) -> None:
        switched = getattr(self.view, "control_switched", None)
        if switched is not None:
            switched(control)
        self.view_visibility_changed.emit()

    def _focus_control(self, control) -> None:
        focus = getattr(self.view, "focus_control", None)
        if focus is not None:
            focus(control)

    def _status_function(self, func) -> None:
        hook = getattr(self.view, "set_status_function", None)
        if hook is not None:
            hook(func)

    #
    # What InfoDock asks of its owner
    #

    def set_synchronized_cursor_address(self, address: int | None) -> None:
        owner = self.view if isinstance(self.view, Synchronized) and self.view is not self else self
        if owner is self:
            Synchronized.set_synchronized_cursor_address(self, address)
        else:
            owner.set_synchronized_cursor_address(address)

    def set_synchronized_highlight_regions(self, regions) -> None:
        owner = self.view if isinstance(self.view, Synchronized) and self.view is not self else self
        if owner is self:
            Synchronized.set_synchronized_highlight_regions(self, regions)
        else:
            owner.set_synchronized_highlight_regions(regions)

    def show_instruction(self, insn_addr, insn_pos=None, use_animation: bool | None = None) -> None:
        """Scroll the shown control to the instruction at ``insn_addr``; the control animates by its own default."""
        if self.current_graph is None:
            return
        if use_animation is None:
            self.current_graph.show_instruction(insn_addr, insn_pos=insn_pos)
        else:
            self.current_graph.show_instruction(insn_addr, insn_pos=insn_pos, use_animation=use_animation)

    #
    # Properties
    #

    @property
    def kb(self) -> Any:
        """The instance's knowledge base (None before a project is loaded)."""
        return self.instance.kb

    @property
    def project(self) -> Any:
        """The instance's project container."""
        return self.instance.project

    @property
    def disassembly_level(self) -> DisassemblyLevel:
        return self._disassembly_level

    @property
    def disasm(self):
        return getattr(self.graph, "disasm", None)

    @property
    def show_minimap(self) -> bool:
        return self._show_minimap

    @property
    def smart_highlighting(self) -> bool:
        if self.graph is None or self.infodock is None:
            return False
        return self.infodock.smart_highlighting

    @property
    def show_address(self) -> bool:
        return self._show_address

    @property
    def show_variable(self) -> bool:
        return self._show_variable

    @property
    def show_variable_identifier(self) -> bool:
        return self._show_variable_ident

    @property
    def show_exception_edges(self) -> bool:
        return self._show_exception_edges

    @property
    def variable_recovery_flavor(self) -> str:
        return self._variable_recovery_flavor

    @variable_recovery_flavor.setter
    def variable_recovery_flavor(self, v: str) -> None:
        if v in ("fast", "accurate") and v != self._variable_recovery_flavor:
            self._variable_recovery_flavor = v

    @property
    def current_graph(self) -> Any:
        """The control shown now: the linear viewer or the flow graph."""
        return self._current_view

    @property
    def current_function(self) -> ObjectContainer:
        return self.function

    @property
    def is_linear(self) -> bool:
        return self._current_view is not None and self._current_view is self.linear

    @property
    def keymap(self) -> Keymap:
        return disassembly_keymap()

    def commands(self) -> list:
        return [
            cmd for cmd in self.workspace.command_manager.get_commands() if cmd.name.startswith("disassembly_view_")
        ]

    #
    # The analyses shown
    #

    def graph_disasm(self, func: Function, level: DisassemblyLevel | None = None):
        """The analysis the graph shows ``func`` with: its Clinic for AIL (the decompiler's if it has one), else its
        Disassembly, with lifter IR for the lifter IR level. Cached by function."""
        level = self._disassembly_level if level is None else level
        if level is DisassemblyLevel.AIL:
            try:
                # always check if decompiler has cached a clinic object first
                return self.kb.decompilations[(func.addr, "pseudocode")].clinic
            except (KeyError, AttributeError):
                try:
                    return self._graph_ail_disasms[func.addr]
                except KeyError:
                    disasm = self._graph_ail_disasms[func.addr] = self.instance.project.analyses.Clinic(func)
                    return disasm
        include_ir = level is DisassemblyLevel.LifterIR
        cache_key = (func.addr, include_ir)
        try:
            return self._graph_disasms[cache_key]
        except KeyError:
            disasm = self._graph_disasms[cache_key] = self.instance.project.analyses.Disassembly(
                function=func, include_ir=include_ir
            )
            return disasm

    def linear_disasm(self, func: Function, level: DisassemblyLevel | None = None):
        """The analysis the linear view shows ``func`` with, cached by function until the next initialize."""
        level = self._disassembly_level if level is None else level
        if level is DisassemblyLevel.AIL:
            if func.addr not in self._linear_ail_disasms:
                self._linear_ail_disasms[func.addr] = self.instance.project.analyses.Clinic(func)
            return self._linear_ail_disasms[func.addr]
        if func.addr not in self._linear_disasms:
            include_ir = level is DisassemblyLevel.LifterIR
            self._linear_disasms[func.addr] = self.instance.project.analyses.Disassembly(
                function=func, include_ir=include_ir
            )
        return self._linear_disasms[func.addr]

    def clear_linear_disasm_cache(self) -> None:
        self._linear_disasms.clear()
        self._linear_ail_disasms.clear()

    def supergraph_of(
        self, function_graph: FunctionGraph, disasm, level: DisassemblyLevel | None = None
    ) -> tuple[Any, Callable, Callable, bool]:
        """
        The supergraph a graph shows, and how to get each supernode's CFG nodes and out branches, and whether its
        nodes have indices (AIL): what QDisassemblyGraph.reload laid out.
        """
        level = self._disassembly_level if level is None else level
        if level is DisassemblyLevel.AIL:
            supergraph = to_ail_supergraph(disasm.cc_graph)

            def ail_nodes(n):
                return supergraph.nodes[n]["original_nodes"]

            def no_branches(_supernode):
                return None

            return supergraph, ail_nodes, no_branches, True

        def cfg_nodes(n):
            return n.cfg_nodes

        return function_graph.supergraph, cfg_nodes, get_out_branches, False

    #
    # Render models
    #

    def block_options(self, graph: bool = True) -> BlockTreeNodeOptions:
        """What the block tree text of a block shows, as QBlock sets it."""
        options = BlockTreeNodeOptions()
        options.show_conditional_jump_targets = not graph
        options.show_variables = self.show_variable
        options.show_variable_identifiers = self.show_variable_identifier
        return options

    def block_doc(
        self, func_addr: int, disasm, addr: int, cfg_nodes, out_branches, idx=None, options: Any = None
    ) -> BlockDoc:
        """One graph block's lines; ``options`` holds the display options (this presenter's by default)."""
        nodes = build_block_nodes(
            self.instance, func_addr, disasm, self.infodock, cfg_nodes, out_branches, self.block_options()
        )
        display = options if options is not None else self
        lines: list[Line] = []
        owners: list[DisasmNode] = []
        for node in nodes:
            for line in self.node_lines(node, display, linear=False):
                lines.append(line)
                owners.append(node)
        header = next((node.text for node in nodes if isinstance(node, LabelNode)), f"loc_{addr:#x}:")
        return BlockDoc(addr, lines, owners, header=header, idx=idx)

    def graph_doc(
        self,
        function_graph: FunctionGraph | None,
        measure: Callable[[BlockDoc], tuple[int, int]] | None = None,
        options: Any = None,
        **margins: int,
    ) -> tuple[GraphDoc, Any] | None:
        """
        Lay out ``function_graph``: a :class:`GraphDoc` and the analysis it shows, or None for no graph.

        :param measure:     A block's size in the frontend's units; by default, in cells, the widest line plus a
                            border and a space each side, and the lines plus the top and bottom border.
        :param options:     The display options the blocks are drawn with (this presenter's by default).
        :param margins:     The layouter's margins (see :data:`CELL_MARGINS`, the default).
        """
        if function_graph is None:
            return None
        func = function_graph.function
        disasm = self.graph_disasm(func)
        supergraph, nodefunc, branchfunc, has_idx = self.supergraph_of(function_graph, disasm)
        if measure is None:
            measure = cell_size

        doc = GraphDoc()
        for n in supergraph.nodes():
            block = self.block_doc(
                func.addr, disasm, n.addr, nodefunc(n), branchfunc(n), n.idx if has_idx else None, options
            )
            doc.blocks[n] = block
            doc.sizes[n] = measure(block)
            if n.addr == func.addr:
                doc.entry = n
            for insn_addr in block.insn_addrs:
                doc.insn_block[insn_addr] = n
            for node in block.nodes:
                if node.addr is not None and node.addr not in doc.insn_block and not isinstance(node, InsnNode):
                    doc.insn_block.setdefault(node.addr, n)
        if doc.entry is None and doc.blocks:
            doc.entry = doc.insn_block.get(func.addr, next(iter(doc.blocks)))
        doc.graph = supergraph
        self.layout_graph(doc, disasm, None, **margins)
        return doc, disasm

    @staticmethod
    def layout_graph(
        doc: GraphDoc,
        disasm,
        measure: Callable[[BlockDoc], tuple[int, int]] | None = None,
        **margins: int,
    ) -> GraphDoc:
        """
        Place the blocks of ``doc`` and route its edges with GraphLayouter; ``measure`` gives each block's size
        again (after its lines changed), else the sizes in ``doc`` are used. Margins as for :meth:`graph_doc`.
        """
        if measure is not None:
            doc.sizes = {key: measure(block) for key, block in doc.blocks.items()}
        if not doc.blocks or doc.graph is None:
            doc.layout, doc.edges = {}, []
            return doc
        layout_margins = dict(CELL_MARGINS)
        layout_margins.update(margins)
        gl = GraphLayouter(doc.graph, doc.sizes, **layout_margins)
        doc.layout = {node: (int(x), int(y)) for node, (x, y) in gl.node_coordinates.items()}
        categorize_edges(disasm, gl.edges)
        doc.edges = [
            EdgeRoute([(int(x), int(y)) for x, y in edge.coordinates], edge.sort, edge.src.addr, edge.dst.addr)
            for edge in gl.edges
        ]
        return doc

    def marks_at(self, addr: int, view: Any = None) -> list[Mark]:
        """
        The marks of the instruction at ``addr``: hooks, breakpoints, symbolic execution find and avoid addresses,
        and the plugins' ``decorate_insn`` marks, highest priority first.
        """
        marks: list[Mark] = []
        if self.instance.project.am_none:
            return marks
        project = self.instance.project
        if addr in project._sim_procedures:  # pylint:disable=protected-access
            marks.append(Mark("hook", "disasm.mark.hook", "before", 3, lambda a=addr: self._delete_hook(a), addr=addr))
        symexec = self.workspace.view_manager.first_view_in_category("symexec")
        qsimgrs = getattr(symexec, "_simgrs", None)
        if qsimgrs is not None:
            if addr in qsimgrs.find_addrs:
                marks.append(Mark("find", "disasm.mark.find", "before", 2, addr=addr))
            if addr in qsimgrs.avoid_addrs:
                marks.append(Mark("avoid", "disasm.mark.avoid", "before", 2, addr=addr))
        for bp in self.instance.breakpoint_mgr.get_breakpoints_at(addr):
            marks.append(
                Mark(
                    "break",
                    "disasm.mark.break",
                    "before",
                    4,
                    lambda b=bp: self.instance.breakpoint_mgr.remove_breakpoint(b),
                    addr=addr,
                )
            )
        plugins = getattr(self.workspace, "plugins", None)
        if plugins is not None:
            marks.extend(plugins.decorate_insn(addr, view if view is not None else self.view))
        return sorted_marks(marks)

    def insn_background_style(self, node: InsnNode) -> str:
        """The background style key of an instruction line, by :func:`insn_background` (plugins first)."""
        plugins = getattr(self.workspace, "plugins", None)

        def plugin_color(addr: int, selected: bool):
            return plugins.insn_style(addr, selected, self.view) if plugins is not None else None

        background = insn_background(
            node.addr, node.insn.size, self.instance, node.selected, self.pattern_highlight_addrs, plugin_color
        )
        if background is None:
            return ""
        if isinstance(background, str):
            return BACKGROUND_PREFIX + background
        color = to_color(background)
        return f"{BACKGROUND_PREFIX}#{color.rgb_hex}" if color is not None else ""

    def block_background_style(self, addr: int, zoomed_out: bool = False) -> str:
        """
        The background style key of the graph block at ``addr``, by :func:`block_background`: a plugin's colour, the
        zoomed-out colour when the block's text is not drawn, or the block colour.
        """
        plugins = getattr(self.workspace, "plugins", None)
        plugin_color = plugins.block_style if plugins is not None else None
        background = block_background(addr, zoomed_out, plugin_color=plugin_color)
        if isinstance(background, str):
            return BACKGROUND_PREFIX + background
        color = to_color(background)
        return f"{BACKGROUND_PREFIX}#{color.rgb_hex}" if color is not None else BACKGROUND_PREFIX + BLOCK_STYLE

    def node_lines(self, node: DisasmNode, display: Any = None, linear: bool = False, marks: bool = True) -> list[Line]:
        """
        A node's lines as a cell frontend draws them: its text, an instruction's background (selection, pattern,
        patch, bookmark, plugin colour) and its marks (before or after its text, or lines of their own above it).
        """
        lines = node.lines(display if display is not None else self, linear=linear)
        if not isinstance(node, InsnNode):
            return lines
        background = self.insn_background_style(node)
        if marks:
            node_marks = self.marks_at(node.addr)
            if node_marks and lines:
                before = [m for m in node_marks if m.position == "before"]
                after = [m for m in node_marks if m.position == "after"]
                above = [m for m in node_marks if m.position == "line"]
                first = lines[0]
                spans = []
                for mark in before:
                    spans.append(Span(mark.text, mark.style_key or "disasm.mark", mark))
                    spans.append(Span(" ", "", node))
                spans.extend(first.spans)
                for mark in after:
                    spans.append(Span(" ", "", node))
                    spans.append(Span(mark.text, mark.style_key or "disasm.mark", mark))
                lines[0] = Line(spans)
                lines[:0] = [Line([Span(m.text, m.style_key or "disasm.mark", m)]) for m in above]
        if background:
            lines = [line.restyled(background) for line in lines]
        return lines

    def block_marks(self, block_addr: int, view: Any = None) -> list[Mark]:
        plugins = getattr(self.workspace, "plugins", None)
        if plugins is None:
            return []
        return plugins.block_marks(block_addr, view if view is not None else self.view)

    def _delete_hook(self, addr: int) -> None:
        self.instance.delete_hook(addr)
        self.refresh()

    #
    # Events
    #

    def register_events(self) -> None:
        if self._events_registered:
            return
        self._events_registered = True
        self.infodock.selected_insns.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_insns.am_subscribe(self.update_highlight_regions_for_synchronized_views)
        self.infodock.selected_insns.am_subscribe(self._on_insn_selection_changed)
        self.infodock.selected_operands.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_blocks.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_block.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_edge.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_labels.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_variables.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_block_tree_node.am_subscribe(self.redraw_current_graph)
        self.workspace.current_screen.am_subscribe(self.on_screen_changed)
        self.instance.breakpoint_mgr.breakpoints.am_subscribe(self._on_breakpoints_updated)
        container(self.instance.cfb).am_subscribe(self.on_cfb_event)
        self.function.am_subscribe(self._on_function_event)

    def unregister_events(self) -> None:
        if not self._events_registered:
            return
        self._events_registered = False
        self.infodock.selected_insns.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_insns.am_unsubscribe(self.update_highlight_regions_for_synchronized_views)
        self.infodock.selected_insns.am_unsubscribe(self._on_insn_selection_changed)
        self.infodock.selected_operands.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_blocks.am_unsubscribe(self.redraw_current_graph)
        self.infodock.hovered_block.am_unsubscribe(self.redraw_current_graph)
        self.infodock.hovered_edge.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_labels.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_variables.am_unsubscribe(self.redraw_current_graph)
        self.infodock.selected_block_tree_node.am_unsubscribe(self.redraw_current_graph)
        self.workspace.current_screen.am_unsubscribe(self.on_screen_changed)
        self.instance.breakpoint_mgr.breakpoints.am_unsubscribe(self._on_breakpoints_updated)
        container(self.instance.cfb).am_unsubscribe(self.on_cfb_event)

    def close(self) -> None:
        self.unregister_events()
        self.desync()

    def _on_breakpoints_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.view_or_self("refresh")()

    def view_or_self(self, name: str) -> Callable:
        """The view's ``name`` method if it has one, else this presenter's (what the Qt view overrides)."""
        return self._view_method(name) or getattr(self, name)

    def _on_function_event(self, **kwargs) -> None:  # pylint:disable=unused-argument
        # the event was fired by display_function_without_history itself; re-displaying would re-record the function
        # head in the jump history and scroll away from the jump target
        if self._displaying_function:
            return
        self.display_function(self.function.am_obj, send_event=False)

    def on_cfb_event(self, **kwargs) -> None:
        if not kwargs:
            self._find_text_cache.clear()
            if self.instance.project.am_none:
                # the binary was closed: clear both the graph and linear viewer
                self.function.am_obj = None
                if self.graph is not None:
                    self.graph.function_graph = None
                if self.linear is not None:
                    self.linear.reload()
                return
            self.reload_current_function_if_changed()
            if self.linear is not None:
                self.linear.reload()
        elif "objects_added" in kwargs:
            # incremental event during CFG recovery; note that this may run on the job worker thread
            now = time.monotonic()
            if now - self._last_objects_added_refresh < MIN_OBJECTS_ADDED_REFRESH_INTERVAL:
                return
            self._last_objects_added_refresh = now
            gui_thread_schedule_async(self.refresh_linear_viewer_on_objects_added, args=(kwargs["objects_added"],))

    def refresh_linear_viewer_on_objects_added(self, objects) -> None:
        """
        Refresh the linear viewer if any of the newly added CFB objects land within the visible address range.
        """
        if self._current_view is not self.linear or self.linear is None:
            return
        addr_range = self.linear.visible_addr_range()
        if addr_range is None:
            return
        range_start, range_end = addr_range
        if any(addr < range_end and addr + max(obj.size or 1, 1) > range_start for addr, obj in objects):
            self.linear.refresh_objects()

    def on_cc_recovered(self, func_addr: int) -> None:
        if not self.function.am_none and self.function.addr == func_addr:
            self.view_or_self("reload")()

    def on_variable_recovered(self, func_addr: int) -> None:
        if not self.function.am_none and self.function.addr == func_addr:
            self.view_or_self("reload")()

    def on_screen_changed(self, **kwargs) -> None:  # pylint:disable=unused-argument
        if self._current_view is not None:
            self._current_view.refresh()

    def on_synchronized_cursor_address_changed(self) -> None:
        """
        Other views use real addresses while jump_to() uses odd addresses for ARM-THUMB mode instructions, so the
        synchronized cursor jumps with ``is_real_addr``. The presenter is the synchronized participant where its view
        is not one (the terminal); the Qt view is one and keeps its own copy of this method.
        """
        assert not self._processing_synchronized_cursor_update
        self._processing_synchronized_cursor_update = True
        try:
            if self.sync_state.cursor_address is not None:
                self.jump_to(self.sync_state.cursor_address, is_real_addr=True)
        finally:
            self._processing_synchronized_cursor_update = False

    #
    # Drawing
    #

    def reload(self) -> None:
        old_infodock = self.infodock.copy()
        self.infodock.initialize()
        # Reload the current graph to make sure it gets the latest information, such as variables.
        self.reload_current_function_if_changed()
        if self._current_view is not None:
            self._current_view.reload(old_infodock=old_infodock)

    def refresh(self) -> None:
        if self._current_view is not None:
            self._current_view.refresh()

    def redraw_current_graph(self, **kwargs) -> None:  # pylint: disable=unused-argument
        """Redraw the control shown now."""
        if self._current_view is not None:
            self._current_view.redraw()

    def highlight_pattern_addrs(self, addrs) -> None:
        """Paint the instructions at ``addrs``, replacing any earlier pattern highlight."""
        self.pattern_highlight_addrs = set(addrs)
        self.redraw_current_graph()

    def clear_pattern_highlight(self) -> bool:
        """Drop the pattern highlight; returns whether there was one."""
        had = bool(self.pattern_highlight_addrs)
        self.pattern_highlight_addrs = set()
        if had:
            self.redraw_current_graph()
        return had

    def reload_current_function_if_changed(self) -> None:
        graph = self.graph
        if graph is not None and graph.function_graph is not None:
            func_addr = graph.function_graph.function.addr
            try:
                func = self.kb.functions.get_by_addr(func_addr)
            except KeyError:
                func = None
            if graph.function_graph.function is not func:
                self.display_function_without_history(func)
            if func is None:
                self.jump_to_without_history(func_addr)

    #
    # Levels and options
    #

    @needs_gui_thread
    def set_disassembly_level(self, level: DisassemblyLevel) -> None:
        self._disassembly_level = level
        if self.graph is not None:
            self.graph.set_disassembly_level(level)
        if self.linear is not None:
            self.linear.set_disassembly_level(level)
        self.level_changed.emit(level)
        self.redraw_current_graph()

    def set_disassembly_level_ail(self) -> None:
        self.view_or_self("set_disassembly_level")(DisassemblyLevel.AIL)

    def set_disassembly_level_lifter_ir(self) -> None:
        self.view_or_self("set_disassembly_level")(DisassemblyLevel.LifterIR)

    def set_disassembly_level_machine_code(self) -> None:
        self.view_or_self("set_disassembly_level")(DisassemblyLevel.MachineCode)

    def toggle_show_minimap(self, show_minimap: bool | None = None) -> None:
        if show_minimap is None:
            show_minimap = not self._show_minimap
        self._show_minimap = show_minimap
        self.refresh()

    def toggle_smart_highlighting(self, enabled: bool | None = None) -> None:
        """Toggle between the smart highlighting mode and the text-based highlighting mode."""
        if enabled is None:
            enabled = not self.infodock.smart_highlighting
        self.infodock.smart_highlighting = enabled
        if self.graph is not None:
            self.graph.refresh()
        if self.linear is not None:
            self.linear.refresh()

    def toggle_show_address(self, show_address: bool | None = None) -> None:
        if show_address is None:
            show_address = not self._show_address
        self._show_address = show_address
        self.refresh()

    def toggle_show_variable(self, show_variable: bool | None = None) -> None:
        if show_variable is None:
            show_variable = not self._show_variable
        self._show_variable = show_variable
        self.refresh()

    def toggle_show_variable_identifier(self, show_ident: bool | None = None) -> None:
        if show_ident is None:
            show_ident = not self._show_variable_ident
        self._show_variable_ident = show_ident
        self.refresh()

    def toggle_show_exception_edges(self, show_exception_edges: bool | None = None) -> None:
        """Show or hide exception edges and the nodes only they reach."""
        if show_exception_edges is None:
            show_exception_edges = not self._show_exception_edges
        if show_exception_edges != self._show_exception_edges:
            self._show_exception_edges = show_exception_edges
            graph = self.graph
            if graph is not None and graph.function_graph is not None:
                graph.function_graph.exception_edges = show_exception_edges
                graph.function_graph.clear_cache()
                graph.reload()

    def run_induction_variable_analysis(self) -> None:
        graph = self.graph
        if self.infodock.induction_variable_analysis:
            self.infodock.induction_variable_analysis = None
        elif graph is not None and graph.function_graph is not None:
            analyses = self.instance.project.analyses
            self.infodock.induction_variable_analysis = analyses.AffineRelationAnalysis(graph.function_graph.function)
        if graph is not None:
            graph.refresh()

    def options_menu(self) -> Menu:
        """The Options menu: the display toggles, checked as they are now."""
        return DisasmOptionsMenu(self)

    def level_menu(self) -> Menu:
        """The level selector as a menu."""
        menu = Menu("&Level")
        for level, name in LEVEL_NAMES.items():
            menu.add(
                MenuEntry(
                    name,
                    lambda _checked=True, lv=level: self.view_or_self("set_disassembly_level")(lv),
                    checkable=True,
                    checked=level is self._disassembly_level,
                )
            )
        return menu

    #
    # Graph or linear
    #

    def toggle_disasm_view(self, prefer: bool = True) -> None:
        if self._current_view is self.linear:
            self.view_or_self("display_disasm_graph")(prefer)
        else:
            self.view_or_self("display_linear_viewer")(prefer)

    @needs_gui_thread
    def display_disasm_graph(self, prefer: bool = True) -> None:
        if prefer:
            self._prefer_graph = True
        graph = self.graph
        self._current_view = graph
        self._show_control(graph)

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self.jump_to_without_history(next(iter(self.infodock.selected_insns)))
        elif self.function.am_obj is not None:
            graph.show_instruction(self.function.addr)

        self._control_switched(graph)
        graph.refresh()
        self._refresh_find_matches_for_view_switch()

    @needs_gui_thread
    def display_linear_viewer(self, prefer: bool = True) -> None:
        if prefer:
            self._prefer_graph = False
        linear = self.linear
        self._current_view = linear
        self._show_control(linear)

        if self.infodock.selected_insns:
            # display the currently selected instruction
            linear.show_instruction(next(iter(self.infodock.selected_insns)))
        elif self.function.am_obj is not None:
            linear.show_instruction(self.function.addr)

        self._control_switched(linear)
        linear.refresh()
        self._refresh_find_matches_for_view_switch()

    #
    # Navigation
    #

    def display_function(self, function, send_event: bool = True) -> None:
        if function is None:
            return
        self.workspace.note_user_navigation()
        self.jump_history.jump_to(function.addr)
        self.display_function_without_history(function, send_event=send_event)

    def decompile_current_function(self) -> None:
        if self.function.am_obj is not None:
            try:
                curr_ins = next(iter(self.infodock.selected_insns))
            except StopIteration:
                curr_ins = None
            self.workspace.decompile_function(self.function.am_obj, curr_ins=curr_ins)

    def jump_to(self, addr: int, src_ins_addr=None, use_animation: bool = False, is_real_addr: bool = False) -> bool:
        # Do not jump if addr is not in the binary
        if addr is None or (
            not self.instance.project.am_none and self.instance.project.loader.find_object_containing(addr) is None
        ):
            return False

        self.workspace.note_user_navigation()

        # Record the current instruction address
        if src_ins_addr is not None:
            self.jump_history.record_address(src_ins_addr)

        self.jump_history.jump_to(addr)
        self.jump_to_without_history(addr, use_animation=use_animation, is_real_addr=is_real_addr)
        return True

    def jump_back(self) -> None:
        addr = self.jump_history.backtrack()
        if addr is not None:
            self.workspace.note_user_navigation()
            self.jump_to_without_history(addr, use_animation=False)

    def jump_forward(self) -> None:
        addr = self.jump_history.forwardstep()
        if addr is not None:
            self.workspace.note_user_navigation()
            self.jump_to_without_history(addr, use_animation=False)

    def jump_to_history_position(self, pos: int) -> None:
        addr = self.jump_history.step_position(pos)
        if addr is not None:
            self.workspace.note_user_navigation()
            self.jump_to_without_history(addr, use_animation=False)

    def history_menu(self) -> Menu:
        """The jump history, newest first, as a menu of entries that go there (the Nav toolbar's drop-down)."""
        menu = Menu("&History")
        history = self.jump_history.history
        for pos in reversed(range(len(history))):
            addr = history[pos]
            func = locate_function(self.instance, addr) if not self.instance.project.am_none else None
            caption = f"{addr:#x}" if func is None else f"{func.name}+{addr - func.addr:#x} ({addr:#x})"
            menu.add(
                MenuEntry(
                    caption,
                    lambda _checked=True, p=pos: self.jump_to_history_position(p),
                    checkable=True,
                    checked=pos == self.jump_history.pos,
                )
            )
        return menu

    def select_label(self, label_addr) -> None:
        self.infodock.select_label(label_addr)

    def display_function_without_history(self, the_func, send_event: bool = True) -> None:
        if the_func is not None:
            self.set_synchronized_cursor_address(the_func.addr)

        self.function.am_obj = the_func
        if send_event:
            self._displaying_function = True
            try:
                self.function.am_event()
            finally:
                self._displaying_function = False

        # set status bar
        self._status_function(the_func)

        # variable recovery
        variable_manager = self.instance.project.kb.variables
        self.variable_manager = variable_manager
        self.infodock.variable_manager = variable_manager

        # clear existing selected instructions and operands
        self.infodock.clear_selection()

        graph = self.graph
        if graph.function_graph is None or graph.function_graph.function is not the_func:
            graph.function_graph = (
                None
                if the_func is None
                else FunctionGraph(function=the_func, exception_edges=self.show_exception_edges)
            )
        elif self._current_view is graph and the_func is not None:
            graph.show_instruction(the_func.addr)

        if the_func is not None:
            if not the_func.block_addrs_set:
                # the function has no blocks yet (e.g., it was created at a call site during CFG recovery before its
                # body has been traced); an empty graph view is useless - show the location in the linear view
                # instead, without changing the user's graph-view preference
                if self._current_view is not self.linear:
                    self.view_or_self("display_linear_viewer")(prefer=False)
            elif self._prefer_graph and self._current_view is self.linear:
                # restore the preferred graph view (e.g., after a block-less function was routed to the linear view)
                self.view_or_self("display_disasm_graph")(prefer=False)

        if self._current_view is self.linear and the_func is not None:
            self.linear.navigate_to_addr(the_func.addr)

        console_view = self.workspace.view_manager.first_view_in_category("console")
        if console_view is not None:
            console_view.set_current_function(the_func)

    def jump_to_without_history(self, addr: int, use_animation: bool = False, is_real_addr: bool = False) -> bool:
        if self._prefer_graph and self._current_view is self.linear:
            self.view_or_self("display_disasm_graph")(prefer=False)

        # real_addr is the address in RAM regardless of the ARM/THUMB mode
        # code_addr is an address that guarantees to hit the correct instruction
        real_addr = addr
        code_addr = addr
        is_arm = is_arm_arch(self.instance.project.arch) if not self.instance.project.am_none else False
        if is_arm and is_real_addr and code_addr & 1 == 0:
            code_addr = addr + 1  # ensures we always hit the middle of an instruction regardless of ARM/THUMB

        if self._current_view is not self.linear:
            function = locate_function(self.instance, code_addr)
            if function is not None:
                graph = self.graph
                if (
                    function is not self.function.am_obj
                    or graph.function_graph is None
                    or graph.function_graph.function is not function
                ):
                    # only switch functions when needed; re-displaying the current one scrolls to its head
                    self.display_function_without_history(function)
                instr_addr = function.addr_to_instruction_addr(code_addr)
                if instr_addr is None:
                    instr_addr = code_addr
                self.infodock.select_instruction(instr_addr, unique=True, use_animation=use_animation)
                return True

            # it does not belong to any function - we need to switch to linear view mode
            self.view_or_self("display_linear_viewer")(prefer=False)

        try:
            _, item = container(self.instance.cfb).floor_item(code_addr)
            if (
                code_addr != real_addr
                and isinstance(item, MemoryData)
                and (code_addr < item.addr or code_addr >= item.addr + item.size)
            ):
                # expect code but found memory data - try the real address instead
                _, item = container(self.instance.cfb).floor_item(real_addr)

            if isinstance(item, MemoryData) and addr < (item.addr + item.size):
                self.infodock.select_label(item.addr)
            elif isinstance(item, Block) and item.size and code_addr < (item.addr + item.size):
                addr = max(a for a in item.instruction_addrs if a <= code_addr)
                self.infodock.select_instruction(addr, unique=True, use_animation=use_animation)
                return True  # select_instruction will navigate
        except KeyError:
            pass

        self.linear.navigate_to_addr(addr)
        return True

    #
    # Selection
    #

    def _on_insn_selection_changed(self, **kwargs) -> None:
        """
        In linear view, make the current function follow the selected instruction so the status bar and function-scoped
        actions refer to the function that was actually clicked.
        """
        if self._current_view is not self.linear or self.instance.project.am_none:
            return
        insn_addr = kwargs.get("insn_addr")
        if insn_addr is None:
            return
        func = None
        func_addr = self.linear.function_addr_of_instruction(insn_addr)
        if func_addr is not None:
            with contextlib.suppress(KeyError):
                func = self.kb.functions.get_by_addr(func_addr)
        if func is None:
            func = locate_function(self.instance, insn_addr)
        shown: Any = self.function.am_obj
        if func is None or (shown is not None and shown.addr == func.addr):
            return
        # update quietly: firing the container event would navigate away and clear the selection
        self.function.am_obj = func
        self._status_function(func)

    def update_highlight_regions_for_synchronized_views(self, **kwargs) -> None:  # pylint: disable=unused-argument
        """Highlight each selected instruction in synchronized views."""
        regions = []
        is_arm = is_arm_arch(self.instance.project.arch) if not self.instance.project.am_none else False
        for addr in self.infodock.selected_insns:
            s = self.get_instruction_size(addr)
            if s is not None:
                real_addr = addr & 0xFFFF_FFFE if is_arm else addr
                regions.append(SynchronizedHighlightRegion(real_addr, s))
        self.set_synchronized_highlight_regions(regions)

    @contextlib.contextmanager
    def context_menu_address(self, addr: int):
        """Within the block, the actions act on the instruction at ``addr`` (:attr:`insn_addr_on_context_menu`)."""
        self.insn_addr_on_context_menu = addr
        try:
            yield
        finally:
            self.insn_addr_on_context_menu = None

    def address_in_selection(self) -> tuple[str, int] | None:
        if self.insn_addr_on_context_menu is not None:
            return "insn", self.insn_addr_on_context_menu
        if len(self.infodock.selected_operands) == 1:
            selected_operand: OperandDescriptor = next(iter(self.infodock.selected_operands.values()))
            if selected_operand.num_value is not None:
                return "operand", selected_operand.num_value
        if len(self.infodock.selected_insns) == 1:
            return "insn", next(iter(self.infodock.selected_insns))
        if len(self.infodock.selected_labels) == 1:
            return "insn", next(iter(self.infodock.selected_labels))
        if (
            isinstance(self.infodock.selected_block_tree_node.am_obj, tuple)
            and len(self.infodock.selected_block_tree_node.am_obj) == 2
        ):
            ty, addr = self.infodock.selected_block_tree_node.am_obj
            if ty == "func_name":
                return ty, addr
        return None

    def comment_address_in_selection(self) -> int | None:
        """The address to comment on: the selected instruction, or the function whose name is selected."""
        # the Qt view's own selection helpers win (its code and tests use them)
        addr = (self._view_method("_instruction_address_in_selection") or self.instruction_address_in_selection)()
        if addr is not None:
            return addr
        selection = (self._view_method("_address_in_selection") or self.address_in_selection)()
        if selection is not None and selection[0] == "func_name":
            return selection[1]
        return None

    def instruction_address_in_selection(self) -> int | None:
        if self.insn_addr_on_context_menu is not None:
            return self.insn_addr_on_context_menu
        if len(self.infodock.selected_insns) == 1:
            return next(iter(self.infodock.selected_insns))
        if len(self.infodock.selected_labels) == 1:
            return next(iter(self.infodock.selected_labels))
        return None

    def get_instruction_size(self, addr: int) -> int | None:
        kb = self.instance.project.kb
        f = kb.functions.floor_func(addr)
        if f is None:
            return None
        return f.instruction_size(addr)

    def get_selected_operand_info(self):
        """``(block, insn addr, operand)`` of the first selected operand in the graph, or None."""
        graph = self.graph
        return graph.get_selected_operand_info() if graph is not None else None

    #
    # Code and data
    #

    def define_code(self) -> None:
        """Redefine selected data as code."""
        if self.infodock.selected_labels:
            self.workspace.define_code(next(iter(self.infodock.selected_labels)))

    def undefine_code(self) -> None:
        """Undefine selected instruction as code, mark it as data."""
        if self.infodock.selected_insns:
            self.workspace.undefine_code(next(iter(self.infodock.selected_insns)))

    def resume_cfg_from(self, addr: int) -> None:
        self.workspace.resume_cfg_recovery(addr)

    def resume_cfg_full(self) -> None:
        self.workspace.resume_cfg_recovery_full()

    def update_resume_cfg_entries(self, menu, addr: int) -> None:
        """Enable the resume-CFG-recovery entries of ``menu`` when the recovery can be resumed."""
        if self.workspace.can_resume_cfg_recovery(addr):
            menu.resume_cfg_here_entry.enable()
        else:
            menu.resume_cfg_here_entry.disable()
        if self.workspace.can_resume_cfg_recovery():
            menu.resume_cfg_full_entry.enable()
        else:
            menu.resume_cfg_full_entry.disable()

    def rename_label(self, addr: int, new_name: str, is_func: bool = False, full_refresh: bool = False) -> None:
        graph = self.graph
        if graph is None or graph.disasm is None:
            return
        is_renaming = False

        kb = graph.disasm.kb
        if is_func:
            func = kb.functions.get_by_addr(addr)
            is_renaming = True
            if new_name:
                func.name = new_name
            else:
                # restore to the default name
                func.name = f"sub_{addr:x}"
        elif new_name == "":
            if addr in kb.labels:
                del kb.labels[addr]
        else:
            if addr in kb.labels:
                is_renaming = True
            kb.labels[addr] = new_name

        # callback first
        callback: Any = self.instance.label_rename_callback
        if callback:
            callback(addr=addr, new_name=new_name)

        if full_refresh:
            # redraw the entire graph. required if a data address is renamed.
            graph.refresh()
        else:
            # redraw the current block
            graph.update_label(addr, is_renaming=is_renaming)

    #
    # Comments and bookmarks
    #

    def begin_inline_comment(self, addr: int | None = None) -> Any:
        """
        Start editing the comment at ``addr`` (the selection's by default). A multi-line comment opens the comment
        dialog instead. The terminal asks for the line in a prompt.
        """
        own = self._view_method("begin_inline_comment")
        if own is not None:
            return own(addr)
        if addr is None:
            addr = self.comment_address_in_selection()
        if addr is None:
            return None
        kb = self.kb
        text = "" if kb is None else kb.comments.get(addr, "")
        if "\n" in text:
            with self.context_menu_address(addr):
                self.popup_comment_dialog()
            return None

        def then(answer: str | None) -> None:
            if answer is not None:
                self.workspace.set_comment(addr, answer)

        ask_text("Comment", f"Comment at {addr:#x}:", text, then)
        return None

    def set_comment(self, addr: int, text: str) -> None:
        self.workspace.set_comment(addr, text)

    def set_function_comment(self, addr: int | None = None) -> None:
        """Edit the comment shown as a header block above the containing function."""
        if addr is None:
            addr = self.comment_address_in_selection()
        if addr is None:
            return
        kb = self.kb
        if kb is None:
            return
        func = kb.functions.floor_func(addr)
        if func is None:
            return
        self.instance.annotations.set_kind(func.addr, CommentKind.FUNCTION)
        self.view_or_self("begin_inline_comment")(func.addr)

    def toggle_repeatable_comment(self, addr: int | None = None) -> None:
        """Flip the comment at ``addr`` between repeatable and its default kind."""
        if addr is None:
            addr = self.comment_address_in_selection()
        if addr is None:
            return
        annotations = self.instance.annotations
        is_repeatable = annotations.kind_of(addr) == CommentKind.REPEATABLE
        annotations.set_kind(addr, None if is_repeatable else CommentKind.REPEATABLE)
        annotations.notify_comments_changed(addr)
        self.view_or_self("refresh")()

    def toggle_bookmark_at_selection(self) -> None:
        addr = self.comment_address_in_selection()
        if addr is not None:
            self.workspace.toggle_bookmark(addr)

    def toggle_bookmark(self, addr: int | None = None) -> None:
        if addr is None:
            self.toggle_bookmark_at_selection()
        else:
            self.workspace.toggle_bookmark(addr)

    #
    # Prompts. A view that has its own dialog for one of these (the Qt view) is asked first.
    #

    def popup_jumpto_dialog(self) -> None:
        own = self._view_method("popup_jumpto_dialog")
        if own is not None:
            own()
            return

        def then(values: dict[str, Any] | None) -> None:
            addr = None if values is None else address_of_text(self.instance, values["address"])
            if addr is not None:
                self.jump_to(addr)

        # the Qt JumpTo dialog's box: OK only while the text is an address, a function name or a label
        ask_form(jump_to_form(self.instance), then)

    def resolve_address(self, text: str) -> int | None:
        """An address from what the user typed: a number (hex with or without 0x), a function name or a label."""
        if self.instance.project.am_none:
            return None
        kb = self.kb
        with contextlib.suppress(KeyError):
            return kb.functions[text].addr
        for addr, name in kb.labels.items():
            if name == text:
                return addr
        with contextlib.suppress(ValueError):
            return int(text, 16)
        with contextlib.suppress(ValueError):
            return int(text, 0)
        return None

    def popup_comment_dialog(self) -> None:
        own = self._view_method("popup_comment_dialog")
        if own is not None:
            own()
            return
        addr = self.instruction_address_in_selection()
        if addr is None:
            return
        kb = self.kb
        text = "" if kb is None else kb.comments.get(addr, "")

        def then(values: dict[str, Any] | None) -> None:
            if values is not None:
                # the Qt dialog's comment box strips what it holds
                self.workspace.set_comment(addr, values["comment"].strip())

        ask_form(set_comment_form(text), then)

    def popup_rename_label_dialog(self) -> None:
        own = self._view_method("popup_rename_label_dialog")
        if own is not None:
            own()
            return
        selection = self.address_in_selection()
        if selection is None:
            return
        type_, label_addr = selection
        kb = self.kb
        is_func = type_ == "func_name"
        if is_func:
            current = kb.functions.get_by_addr(label_addr).name
        else:
            current = kb.labels.get(label_addr, "") if label_addr in kb.labels else get_label_text(label_addr, kb)
            current = current.rstrip(":")

        def then(values: dict[str, Any] | None) -> None:
            name = None if values is None else label_name(values["name"])
            if name is not None:
                self.rename_label(label_addr, name, is_func=is_func, full_refresh=type_ == "operand")

        ask_form(rename_label_form(label_addr, current), then)

    def rename_selected_object(self) -> None:
        """Rename the selected variable (a block tree variable node)."""
        own = self._view_method("rename_selected_object")
        if own is not None:
            own()
            return
        obj = self.infodock.selected_block_tree_node.am_obj
        if not isinstance(obj, QVariableObj):
            return

        def then(answer: str | None) -> None:
            if answer:
                obj.obj.name = answer
                self.refresh()

        ask_text("Rename Variable", "New name:", obj.obj.name, then)

    def xrefs_target(self) -> dict[str, Any] | None:
        """
        What the X key shows cross-references to (QDisassemblyBaseControl.keyPressEvent): a selected operand
        (``{"operand": (insn addr, operand)}``), label, variable or function name, as keyword arguments for
        popup_xref_dialog; None when nothing suitable is selected.
        """
        r = self.get_selected_operand_info()
        if r is not None:
            _, ins_addr, operand = r
            return {"operand": (ins_addr, operand)}
        if len(self.infodock.selected_labels) == 1:
            lbl_addr = next(iter(self.infodock.selected_labels))
            return {"addr": lbl_addr, "dst_addr": lbl_addr}
        if len(self.infodock.selected_variables) == 1:
            variable = next(iter(self.infodock.selected_variables))
            return {"addr": 0, "variable": variable}
        if not self.infodock.selected_block_tree_node.am_none:
            selected = self.infodock.selected_block_tree_node.am_obj
            if isinstance(selected, tuple) and len(selected) == 2 and selected[0] == "func_name":
                return {"addr": selected[1], "dst_addr": selected[1]}
        return None

    def xrefs_for_selection(self) -> None:
        """Show the cross-references of the selection, or say what to select."""
        target = self.xrefs_target()
        if target is None:
            GlobalInfo.ui_services.message(
                "critical",
                "Invalid selection for XRefs",
                "You must select an operand, a label, a variable, or a function header before requesting XRefs.",
            )
            return
        if "operand" in target:
            ins_addr, operand = target["operand"]
            self.view_or_self("parse_operand_and_popup_xref_dialog")(ins_addr, operand)
        else:
            self.view_or_self("popup_xref_dialog")(**target)

    def parse_operand_and_popup_xref_dialog(self, ins_addr, operand) -> None:
        if operand is None:
            return
        if operand.variable is not None:
            self.popup_xref_dialog(addr=ins_addr, variable=operand.variable)
        elif operand.is_constant:
            self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_value)
        elif operand.is_constant_memory:
            self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_memory_value)

    def popup_xref_dialog(self, addr: int | None = None, variable=None, dst_addr=None) -> None:
        own = self._view_method("popup_xref_dialog")
        if own is not None:
            own(addr=addr, variable=variable, dst_addr=dst_addr)
            return
        show = getattr(self.workspace.main_window, "show_xrefs", None)
        if show is None:
            return
        if variable is not None:
            show(addr=addr, variable=variable, variable_manager=self.variable_manager, disassembly_view=self)
        else:
            show(addr=addr, dst_addr=dst_addr, xrefs_manager=self.instance.project.kb.xrefs)

    def popup_patch_dialog(self) -> None:
        own = self._view_method("popup_patch_dialog")
        if own is not None:
            own()
            return
        addr = self.instruction_address_in_selection()
        if addr is None:
            return
        assembler = PatchAssembler(self.instance, addr)

        def then(values: dict[str, Any] | None) -> None:
            if values is not None:
                result = assembler.assemble(values["asm"], values["pad"])
                if result.ok:
                    assembler.apply(result.new_bytes)

        ask_form(assembler.form(), then)

    def _not_in_terminal(self, what: str) -> None:  # pylint:disable=no-self-use
        GlobalInfo.ui_services.message("info", what, f"{what} is not in the terminal yet.")

    def popup_newstate_dialog(self) -> None:
        own = self._view_method("popup_newstate_dialog")
        if own is not None:
            own()
            return
        self._not_in_terminal("Executing symbolically")

    def popup_hook_dialog(self, addr: int | None = None) -> None:
        own = self._view_method("popup_hook_dialog")
        if own is not None:
            own(addr)
            return
        if addr is None:
            addr = self.instruction_address_in_selection()
        if addr is None:
            return

        def then(values: dict[str, Any] | None) -> None:
            if values is not None:
                self.workspace.append_code_to_console(values["code"])

        ask_form(hook_form(addr), then)

    def popup_func_doc_dialog(self, instr_addr) -> None:
        own = self._view_method("popup_func_doc_dialog")
        if own is not None:
            own(instr_addr)
            return
        node_of = getattr(self._current_view, "insn_node", None)
        found = func_doc_target(node_of(instr_addr) if node_of is not None else None)
        if found is not None:
            target, name, doc_tuple = found
            ask_form(func_doc_form(target, name, doc_tuple), lambda _values: None)

    def popup_dependson_dialog(self, addr: int | None = None, use_operand: bool = False, func: bool = False):
        own = self._view_method("popup_dependson_dialog")
        if own is not None:
            return own(addr=addr, use_operand=use_operand, func=func)
        if use_operand:
            r = self.get_selected_operand_info()
            if r is None:
                GlobalInfo.ui_services.message("critical", "No operand", "Please select an operand first.")
                return None
            _, addr, operand = r
            # a branch to a function makes the function the one to depend on, as in the Qt view
            target = getattr(operand, "branch_target", None)
            if operand is not None and not func and target is not None and operand.is_target_func:
                func, addr = True, target
        if addr is None:
            raise ValueError("No address is provided.")  # this is a programming error
        the_func = None
        if func and self.kb is not None:
            with contextlib.suppress(KeyError):
                the_func = self.kb.functions.get_by_addr(addr)

        def then(values: dict[str, Any] | None) -> None:
            run = getattr(self.workspace.main_window, "run_dependency_analysis", None)
            if values is not None and run is not None:
                run(func_addr=addr, func_arg_idx=int(values["arg"]))

        ask_form(depends_on_form(the_func), then)
        return None

    def avoid_addr_in_exec(self, addr: int) -> None:
        own = self._view_method("avoid_addr_in_exec")
        if own is not None:
            own(addr)
            return
        view = self.workspace.view_manager.first_view_in_category("symexec")
        if view is not None:
            view.avoid_addr_in_exec(addr)

    def find_addr_in_exec(self, addr: int) -> None:
        own = self._view_method("find_addr_in_exec")
        if own is not None:
            own(addr)
            return
        view = self.workspace.view_manager.first_view_in_category("symexec")
        if view is not None:
            view.find_addr_in_exec(addr)

    #
    # Context menus
    #

    def instruction_at(self, addr: int) -> Any:
        """
        The angr Instruction at ``addr``, or None. The plugins' instruction menu entries are built from it.

        It is the one in the graph or listing shown when the control has a node for it. Otherwise (the listing has
        scrolled the instruction's block away, or the control keeps no nodes) it is read from the Disassembly of the
        function containing ``addr``, the one the control shown would draw it with, and only then from the graph's.
        """
        node_of = getattr(self._current_view, "insn_node", None)
        node = node_of(addr) if node_of is not None else None
        if node is not None:
            return node.insn
        for disasm in (self._function_disasm_at(addr), self.disasm):
            raw_result_map = getattr(disasm, "raw_result_map", None)
            insn = raw_result_map["instructions"].get(addr) if raw_result_map is not None else None
            if insn is not None:
                return insn
        return None

    def _function_disasm_at(self, addr: int) -> Any:
        """The machine-code or lifter IR Disassembly of the function containing ``addr`` that the control shown uses,
        or None (no function there, or the AIL level, which has no angr Instructions)."""
        kb = self.kb
        if kb is None or self._disassembly_level is DisassemblyLevel.AIL:
            return None
        func = kb.functions.floor_func(addr)
        if func is None:
            return None
        return self.linear_disasm(func) if self.is_linear else self.graph_disasm(func)

    def insn_context_menu(self, insn_addr: int, insn: Any = None) -> Menu:
        """
        The instruction's context menu: the instruction menu, plugin entries and "Synchronize with". The plugins
        get ``insn``, the angr Instruction; when it is not given, the one at ``insn_addr`` in the view.
        """
        menu = DisasmInsnContextMenu(self)
        menu.insn_addr = insn_addr
        self.update_resume_cfg_entries(menu, insn_addr)
        if insn is None:
            insn = self.instruction_at(insn_addr)
        plugins = getattr(self.workspace, "plugins", None)
        extra = list(plugins.build_context_menu_insn(insn)) if plugins is not None and insn is not None else []
        return self._with_view_entries(menu, extra)

    def label_context_menu(self, addr: int, pos: Any = None) -> Menu | None:
        own = self._view_method("label_context_menu")
        if own is not None and pos is not None:
            own(addr, pos)
            return None
        menu = DisasmLabelContextMenu(self)
        menu.addr = addr
        self.update_resume_cfg_entries(menu, addr)
        plugins = getattr(self.workspace, "plugins", None)
        extra = list(plugins.build_context_menu_label(addr)) if plugins is not None else []
        built = self._with_view_entries(menu, extra)
        if pos is None:
            return built
        self._open_menu(built)
        return None

    def unknown_context_menu(self, addr: int) -> Menu:
        menu = DisasmUnknownContextMenu(self)
        menu.addr = addr
        self.update_resume_cfg_entries(menu, addr)
        return self._with_view_entries(menu, [])

    def _with_view_entries(self, menu: Menu, extra: list) -> Menu:
        out = Menu(menu.caption)
        out.entries = menu.items(extra)
        out.add(MenuSeparator())
        out.add(self.synchronize_with_menu())
        # the entries' callbacks and enabled states live on the original menu's entries; keep it alive with them
        out.parent = menu
        return out

    def get_context_menu_for_selected_object(self) -> Menu | None:
        """The context menu of the selected block tree node: the label menu for a function name, Rename for a
        variable."""
        obj = self.infodock.selected_block_tree_node.am_obj
        if isinstance(obj, tuple) and len(obj) == 2:
            ty, addr = obj
            if ty == "func_name":
                menu = DisasmLabelContextMenu(self)
                menu.addr = addr
                return menu
        if isinstance(obj, QVariableObj):
            return Menu("", [MenuEntry("Re&name", self.view_or_self("rename_selected_object"))])
        return None

    def show_context_menu_for_selected_object(self) -> None:
        """Open the context menu of the selected block tree node."""
        own = self._view_method("show_context_menu_for_selected_object")
        if own is not None:
            own()
            return
        menu = self.get_context_menu_for_selected_object()
        if menu is not None:
            self._open_menu(self._with_view_entries(menu, []))

    def _open_menu(self, menu: Menu) -> None:
        open_menu = getattr(self.view, "open_menu", None)
        if open_menu is not None:
            open_menu(menu)

    def context_menu(self, *args, **kwargs) -> Menu | None:  # pylint:disable=unused-argument
        """The menu for the selection: the instruction's, the label's, or the selected node's."""
        insn_addr = self.instruction_address_in_selection()
        if insn_addr is not None and insn_addr in self.infodock.selected_insns:
            return self.insn_context_menu(insn_addr)
        if len(self.infodock.selected_labels) == 1:
            return self.label_context_menu(next(iter(self.infodock.selected_labels)))
        menu = self.get_context_menu_for_selected_object()
        if menu is not None:
            return self._with_view_entries(menu, [])
        out = Menu("")
        out.add(self.synchronize_with_menu())
        return out

    #
    # Find
    #

    def show_find_bar(self) -> None:
        """
        Open the incremental find bar. In graph mode it searches the current function; in linear mode it searches every
        function with at least one instruction on the displayed page, plus the data items on the page.
        """
        self._find_text_cache.clear()
        self.find_bar.activate()
        self.update_find_matches()

    def find_next(self) -> None:
        self._step_find_match(1)

    def find_previous(self) -> None:
        self._step_find_match(-1)

    @property
    def find_matches(self) -> list[tuple[int, str]]:
        return self._find_matches

    @property
    def find_index(self) -> int:
        return self._find_index

    def _find_scope_functions(self) -> list[Any]:
        if self.instance.project.am_none:
            return []
        if self._current_view is self.linear:
            functions: list[Any] = []
            for func_addr in self.linear.visible_function_addrs:
                with contextlib.suppress(KeyError):
                    functions.append(self.kb.functions.get_by_addr(func_addr))
            return functions
        func = self.function.am_obj
        return [func] if func is not None else []

    def _function_details(self, searcher: Searcher, func: Function) -> list[tuple[int, str, bytes]]:
        cached = self._find_text_cache.get(func.addr)
        if cached is None:
            cached = list(searcher.iter_instruction_details(func))
            self._find_text_cache[func.addr] = cached
        return cached

    def _visible_data_items(self) -> list[tuple[int, bytes, str]]:
        """``(address, bytes, label)`` for every data item on the displayed linear page."""
        if self._current_view is not self.linear or self.instance.project.am_none:
            return []
        items = []
        for addr, memory_data in self.linear.visible_memory_data:
            data = b""
            if memory_data.content:
                data = bytes(memory_data.content)[: memory_data.size or None]
            if memory_data.size and len(data) < memory_data.size:
                with contextlib.suppress(KeyError):
                    data += bytes(
                        self.instance.project.loader.memory.load(addr + len(data), memory_data.size - len(data))
                    )
            if not data:
                continue
            items.append((addr, data, get_label_text(addr, self.instance.kb) or ""))
        return items

    def _collect_text_matches(
        self, regex: re.Pattern, instructions_only: bool
    ) -> tuple[list[tuple[int, str]], dict[int, int]]:
        matches: list[tuple[int, str]] = []
        data_matches: dict[int, int] = {}
        limit = Conf.find_match_limit
        searcher = Searcher(self.project.am_obj, kb=self.kb)
        comments = self.kb.comments if not instructions_only else None
        for func in self._find_scope_functions():
            for addr, text, _ in self._function_details(searcher, func):
                comment = comments.get(addr) if comments is not None else None
                if comment:
                    text = f"{text} ; {comment}"
                if regex.search(text):
                    if len(matches) >= limit:
                        self._find_matches_capped = True
                        break
                    matches.append((addr, text))
            if self._find_matches_capped:
                break
        if not instructions_only and not self._find_matches_capped:
            for addr, data, label in self._visible_data_items():
                text = f"{label} {data.decode('latin-1')}".strip()
                if regex.search(text):
                    if len(matches) >= limit:
                        self._find_matches_capped = True
                        break
                    matches.append((addr, text))
                    data_matches[addr] = addr
        matches.sort(key=lambda match: match[0])
        return matches, data_matches

    def _collect_byte_matches(self, pattern: BytePattern) -> tuple[list[tuple[int, str]], dict[int, int]]:
        matches: list[tuple[int, str]] = []
        data_matches: dict[int, int] = {}
        limit = Conf.find_match_limit
        searcher = Searcher(self.project.am_obj, kb=self.kb)

        # collect the byte pieces of the scope: every instruction, plus the visible data items
        pieces: list[tuple[int, bytes, bool, str]] = []  # (addr, bytes, is_data, text)
        seen_addrs: set[int] = set()
        for func in self._find_scope_functions():
            for addr, text, raw in self._function_details(searcher, func):
                if raw and addr not in seen_addrs:
                    seen_addrs.add(addr)
                    pieces.append((addr, raw, False, text))
        for item_addr, data, _ in self._visible_data_items():
            if item_addr not in seen_addrs:
                pieces.append((item_addr, data, True, ""))
        pieces.sort(key=lambda piece: piece[0])

        # merge contiguous pieces into runs so the pattern can match across instruction and instruction/data boundaries
        runs: list[tuple[int, bytearray, list[tuple[int, bool, str]]]] = []
        for addr, raw, is_data, text in pieces:
            if runs and addr == runs[-1][0] + len(runs[-1][1]):
                runs[-1][1].extend(raw)
                runs[-1][2].append((addr, is_data, text))
            elif runs and addr < runs[-1][0] + len(runs[-1][1]):
                continue  # e.g. a block shared by two scope functions
            else:
                runs.append((addr, bytearray(raw), [(addr, is_data, text)]))

        capped = False
        seen_anchors: set[int] = set()
        for run_start, run_bytes, units in runs:
            unit_starts = [unit[0] for unit in units]
            for match_addr in pattern.finditer(bytes(run_bytes), base=run_start):
                unit_addr, is_data, text = units[bisect.bisect_right(unit_starts, match_addr) - 1]
                # instruction matches are anchored at the instruction containing the match start
                if not is_data and unit_addr in seen_anchors:
                    continue
                if len(matches) >= limit:
                    capped = True
                    break
                if is_data:
                    offset = match_addr - run_start
                    matches.append((match_addr, run_bytes[offset : offset + len(pattern)].hex(" ")))
                    data_matches[match_addr] = unit_addr
                else:
                    seen_anchors.add(unit_addr)
                    matches.append((unit_addr, text))
            if capped:
                break
        self._find_matches_capped = capped
        matches.sort(key=lambda match: match[0])
        return matches, data_matches

    def _compute_find_matches(self) -> tuple[list[tuple[int, str]], dict[int, int]] | None:
        """
        Compute the match list for the find bar's current mode and query. Returns None if the query is malformed (with
        the error flagged on the bar).
        """
        self._find_matches_capped = False
        query = self.find_bar.query
        if not query or self.instance.project.am_none:
            self.find_bar.set_error(False)
            return [], {}
        if self.find_bar.mode == self.FIND_MODE_BYTES:
            try:
                pattern = BytePattern.parse(query)
            except SearchError:
                self.find_bar.set_error(True)
                return None
            self.find_bar.set_error(False)
            return self._collect_byte_matches(pattern)
        regex = self.find_bar.compile_query(loose_whitespace=True)
        if regex is None:
            return None
        return self._collect_text_matches(regex, instructions_only=self.find_bar.mode == self.FIND_MODE_TEXT_INSN)

    def update_find_matches(self) -> None:
        """The query or the mode changed: match again from the first match."""
        self.find_bar.set_text_options_visible(self.find_bar.mode != self.FIND_MODE_BYTES)
        self._find_index = -1
        self._find_matches = []
        self._find_data_matches = {}
        result = self._compute_find_matches()
        if result is not None:
            self._find_matches, self._find_data_matches = result
        if not self._find_matches:
            self._clear_find_highlights()
            self.find_bar.set_match_status(0, 0)
        elif self._current_view is self.linear:
            # do not move the viewport while typing; the current match starts at the first match
            # at or after the top of the page
            self._find_index = self._first_match_at_or_after_viewport_top()
            self._apply_find_highlights()
        else:
            self._step_find_match(1)

    def on_linear_viewport_changed(self) -> None:
        """Re-apply the find query to the functions that are visible after the linear view scrolled."""
        if (
            self.find_bar is None
            or not self.find_bar_open()
            or self._current_view is not self.linear
            or self._in_find_refresh
            or not self.find_bar.query
        ):
            return
        self._in_find_refresh = True
        try:
            self._refresh_find_matches()
        finally:
            self._in_find_refresh = False

    def find_bar_open(self) -> bool:
        return self.find_bar is not None and self.find_bar.is_open

    def _refresh_find_matches_for_view_switch(self) -> None:
        """
        The find scope depends on the display mode, so recompute the matches when the view toggles between graph and
        linear (without navigating).
        """
        if not self.find_bar_open() or not self.find_bar.query or self._in_find_refresh:
            return
        self._in_find_refresh = True
        try:
            self._refresh_find_matches()
        finally:
            self._in_find_refresh = False

    def _refresh_find_matches(self) -> None:
        result = self._compute_find_matches()
        if result is None:
            return
        current_addr = (
            self._find_matches[self._find_index][0] if 0 <= self._find_index < len(self._find_matches) else None
        )
        self._find_matches, self._find_data_matches = result
        if not self._find_matches:
            self._find_index = -1
            self._clear_find_highlights()
            self.find_bar.set_match_status(0, 0)
            return
        addrs = [addr for addr, _ in self._find_matches]
        self._find_index = (
            addrs.index(current_addr) if current_addr in addrs else self._first_match_at_or_after_viewport_top()
        )
        self._apply_find_highlights()

    def _first_match_at_or_after_viewport_top(self) -> int:
        top = self.linear.first_visible_instruction_addr
        if top is None:
            return 0
        return next((i for i, (addr, _) in enumerate(self._find_matches) if addr >= top), 0)

    def _apply_find_highlights(self) -> None:
        """Apply the highlight set and the match counter for the current match list, without moving the viewport."""
        highlighted = self._find_insn_highlight_set()
        if 0 <= self._find_index < len(self._find_matches):
            current = self._find_matches[self._find_index][0]
            if current not in self._find_data_matches:
                highlighted.add(current)
        self._find_highlighted = True
        self.infodock.unselect_all_labels()
        self.infodock.selected_insns.am_obj = highlighted
        self.infodock.selected_insns.am_event()
        self.find_bar.set_match_status(self._find_index, len(self._find_matches), capped=self._find_matches_capped)

    def _find_insn_highlight_set(self) -> set[int]:
        return {
            addr for addr, _ in self._find_matches[: self.FIND_HIGHLIGHT_LIMIT] if addr not in self._find_data_matches
        }

    def _step_find_match(self, delta: int) -> None:
        if not self._find_matches:
            self.find_bar.set_match_status(0, 0)
            return
        self._find_index = (self._find_index + delta) % len(self._find_matches)
        addr = self._find_matches[self._find_index][0]

        highlighted = self._find_insn_highlight_set()
        data_item_addr = self._find_data_matches.get(addr)
        self._find_highlighted = True
        if data_item_addr is not None:
            # a data match: highlight the data item's label, keep the instruction highlights
            self.infodock.select_label(data_item_addr)
            self.infodock.selected_insns.am_obj = highlighted
            self.infodock.selected_insns.am_event()
        else:
            highlighted.add(addr)
            self.infodock.unselect_all_labels()
            self.infodock.selected_insns.am_obj = highlighted
            self.set_synchronized_cursor_address(get_real_address_if_arm(self.instance.project.arch, addr))
            self.infodock.selected_insns.am_event(insn_addr=addr)
        # navigating may scroll the linear view, which re-applies the query and remaps _find_index
        self._current_view.show_instruction(addr, use_animation=False)
        self.find_bar.set_match_status(self._find_index, len(self._find_matches), capped=self._find_matches_capped)

    def _clear_find_highlights(self) -> None:
        if self._find_highlighted:
            self._find_highlighted = False
            self.infodock.unselect_all_instructions()
            self.infodock.unselect_all_labels()

    def on_find_bar_closed(self) -> None:
        self._find_text_cache.clear()
        # keep only the current match selected
        if self._find_highlighted and 0 <= self._find_index < len(self._find_matches):
            addr = self._find_matches[self._find_index][0]
            self._find_highlighted = False
            if addr in self._find_data_matches:
                # the data item's label selection is the current match; drop the rest
                self.infodock.unselect_all_instructions()
            else:
                self.infodock.selected_insns.am_obj = {addr}
                self.infodock.selected_insns.am_event(insn_addr=addr)
        else:
            self._clear_find_highlights()
        self._find_matches = []
        self._find_data_matches = {}
        self._find_index = -1
        if self._current_view is not None:
            self._focus_control(self._current_view)

    #
    # Plugins
    #

    def activate_insn(self, addr: int, button: str = "left") -> bool:
        """
        The user activated the instruction at ``addr``: plugins' ``handle_activate_insn`` first (True if one
        handled it), then nothing more here; the view selects it.
        """
        plugins = getattr(self.workspace, "plugins", None)
        return bool(plugins is not None and plugins.handle_activate_insn(addr, button, self.view))


__all__ = [
    "CELL_MARGINS",
    "DISASM_COMMANDS",
    "LEVEL_NAMES",
    "BlockDoc",
    "DisasmPresenter",
    "DisassemblyLevel",
    "EdgeRoute",
    "GraphDoc",
    "LinearBlock",
    "LinearSource",
    "disassembly_keymap",
    "register_disasm_commands",
]
