"""
The disassembly view's controls as models: what a frontend that lays out text in cells draws.

:class:`GraphControl` holds a function graph laid out as a :class:`~angrmanagement.present.disasm.GraphDoc` and the
point the viewport should show; :class:`LinearControl` holds the linear listing's position (a byte offset and a line
into the first object) and the lines on screen. Both answer the calls :class:`~angrmanagement.present.disasm.
DisasmPresenter` makes of its controls, the same calls ``QDisassemblyGraph`` and ``QLinearDisassembly`` answer, and
tell the frontend to redraw through ``on_change``. :class:`HeadlessDisasmView` puts a presenter and the two controls
together without drawing anything, for tests and scripts; the terminal's widgets wrap the same controls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.logic.analysis_gate import gate_of
from angrmanagement.logic.signal import Signal

from .block_tree.disasm_nodes import InsnNode, LabelNode, MemoryDataNode
from .disasm import CELL_MARGINS, BlockDoc, DisasmPresenter, GraphDoc, LinearBlock, LinearSource
from .find import FindBarState
from .spans import Line

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.function_graph import FunctionGraph
    from angrmanagement.data.instance import Instance


class GraphControl:
    """
    The graph of one function, laid out in cells.

    :attr:`focus` is an instruction the viewport should show: ``(x, y)`` in the layout's cells; and
    :attr:`reset_pending` asks for the initial view (the entry block). The frontend scrolls and clears both.

    :param presenter:   The disassembly presenter.
    :param on_change:   Called with no arguments when the frontend should draw again.
    """

    def __init__(self, presenter: DisasmPresenter, on_change: Callable[[], Any] | None = None, **margins: int):
        self.presenter = presenter
        self.on_change = on_change
        self.margins = {**CELL_MARGINS, **margins}
        self._function_graph: FunctionGraph | None = None
        self.doc: GraphDoc | None = None
        self.disasm = None
        self.focus: tuple[int, int] | None = None
        self.focus_center = False
        #: the view should first go to the entry block, as a newly laid out graph does
        self.reset_pending = False
        #: the last instruction shown
        self.shown_insn: int | None = None
        self._insaddr_to_block: dict[int, Any] = {}
        self._disassembly_level = presenter.disassembly_level
        self.visible = True
        #: blocks collapsed to their header line
        self.collapsed: set[Any] = set()
        #: while on_change runs for a redraw, the blocks whose lines or frame changed; None means everything
        self.changed_blocks: set[Any] | None = None
        self._drawn_states: dict[Any, tuple] = {}
        #: how much each block shows: 0 everything, 1 no comments, 2 no addresses either, 3 headers only
        self.detail = 0

    @property
    def infodock(self):
        return self.presenter.infodock

    @property
    def function_graph(self) -> FunctionGraph | None:
        return self._function_graph

    @function_graph.setter
    def function_graph(self, function_graph: FunctionGraph | None) -> None:
        if function_graph is not self._function_graph:
            self._function_graph = function_graph
            self.reload()

    @property
    def induction_variable_analysis(self):
        return self.infodock.induction_variable_analysis

    @induction_variable_analysis.setter
    def induction_variable_analysis(self, v) -> None:
        self.infodock.induction_variable_analysis = v

    #
    # What the presenter calls
    #

    def _changed(self) -> None:
        if self.on_change is not None:
            self.on_change()

    def reload(self, old_infodock=None) -> None:
        """Lay the function out again; reselect what ``old_infodock`` had selected, and show the entry."""
        selected_insns = set(old_infodock.selected_insns.am_obj) if old_infodock is not None else set()
        self._layout()
        self._reset_view()
        for insn_addr in selected_insns:
            self.infodock.select_instruction(insn_addr, unique=False, use_animation=False)
        self._changed()

    def _layout(self) -> None:
        self.doc, self.disasm = None, None
        self._insaddr_to_block = {}
        self._drawn_states = {}
        if self._function_graph is None:
            return
        gate = gate_of(self.presenter.instance)
        with gate.access() as granted:
            if not granted:
                # CFG recovery is in a long step and is still adding to this function: lay it out when it is done
                gate.retry_when_done(self.reload)
                return
            result = self.presenter.graph_doc(self._function_graph, self._measure, options=self.display, **self.margins)
        if result is None:
            return
        self.doc, self.disasm = result
        self._insaddr_to_block = dict(self.doc.insn_block)

    def _measure(self, block: BlockDoc) -> tuple[int, int]:
        lines = self.block_lines(block)
        width = max((line.width for line in lines), default=0)
        return width + 4, len(lines) + 2

    @property
    def display(self) -> DetailOptions:
        """The display options at the current level of detail."""
        return DetailOptions(self.presenter, self.detail)

    def block_lines(self, block: BlockDoc) -> list[Line]:
        """The lines a block shows: all of them, or only its header when collapsed (or at the lowest detail)."""
        if self.detail >= 3 or block.addr in self.collapsed:
            return [Line().append(block.header, "disasm_view_label_color")]
        return block.lines

    def set_detail(self, detail: int) -> None:
        """Change the level of detail (0 to 3) and lay out again."""
        self.detail = max(0, min(3, detail))
        self.refresh()

    def toggle_collapsed(self, block_addr: int) -> None:
        """Collapse the block at ``block_addr`` to its header line, or expand it again."""
        self.collapsed.symmetric_difference_update({block_addr})
        self.refresh()

    def refresh(self) -> None:
        """
        Something shown changed (options, comments): read each node's data again and lay the blocks out again,
        keeping the viewport. As QDisassemblyGraph.refresh, the nodes stay; only a reload makes new ones.
        """
        if self.doc is None:
            self._layout()
        else:
            for block in self.doc.blocks.values():
                for node in _unique(block.nodes):
                    node.refresh()
            self.restyle()
            self.presenter.layout_graph(self.doc, self.disasm, self._measure, **self.margins)
            self._insaddr_to_block = dict(self.doc.insn_block)
        self._changed()

    def redraw(self) -> None:
        """The selection changed: draw again the blocks whose text or frame changed (nothing moves)."""
        changed = self.restyle()
        self.changed_blocks = changed
        if self.on_change is not None:
            self.on_change()
        self.changed_blocks = None

    def _block_state(self, key: Any, block: BlockDoc) -> tuple:
        lines = tuple(tuple((span.text, span.style) for span in line.spans) for line in block.lines)
        return lines, self.infodock.is_block_selected(block.addr), key in self.collapsed

    def restyle(self) -> set[Any]:
        """
        Take every block's lines from its nodes again, for their selection and highlight styles; returns the blocks
        whose lines or frame changed.
        """
        changed: set[Any] = set()
        if self.doc is None:
            return changed
        display = self.display
        for key, block in self.doc.blocks.items():
            before = self._block_state(key, block)
            lines: list[Line] = []
            owners = []
            for node in _unique(block.nodes):
                for line in self.presenter.node_lines(node, display, linear=False):
                    lines.append(line)
                    owners.append(node)
            block.lines, block.nodes = lines, owners
            after = self._block_state(key, block)
            if after != before or key not in self._drawn_states or self._drawn_states[key] != after:
                changed.add(key)
            self._drawn_states[key] = after
        return changed

    def set_disassembly_level(self, level) -> None:
        self._disassembly_level = level
        self.reload()

    def show_instruction(  # pylint:disable=unused-argument
        self, insn_addr, insn_pos=None, centering: bool = False, use_block_pos: bool = False, use_animation=False
    ) -> None:
        """Ask the frontend to bring the instruction at ``insn_addr`` into view."""
        position = self.position_of(insn_addr)
        if position is None:
            return
        self.shown_insn = insn_addr
        self.focus = position
        self.focus_center = centering
        self._changed()

    def position_of(self, insn_addr: int, use_block_pos: bool = False) -> tuple[int, int] | None:
        """Where the instruction's line is in the layout: ``(x, y)`` of its first cell."""
        if self.doc is None:
            return None
        key = self._insaddr_to_block.get(insn_addr)
        if key is None or key not in self.doc.layout:
            return None
        x, y = self.doc.layout[key]
        if use_block_pos:
            return x, y
        rows = self.doc.blocks[key].rows_of(insn_addr)
        return x + 2, y + 1 + (rows[0] if rows else 0)

    def _reset_view(self) -> None:
        """Show the top of the entry block (QDisassemblyGraph._initial_position) once the frontend can."""
        self.focus = None
        self.shown_insn = None
        self.reset_pending = False
        if self.doc is None or self.doc.entry is None or self.doc.entry not in self.doc.layout:
            return
        self.reset_pending = True
        self.focus_center = False

    def insn_node(self, insn_addr: int) -> InsnNode | None:
        """The node of the instruction at ``insn_addr`` in the graph, or None."""
        key = self._insaddr_to_block.get(insn_addr)
        if key is None or self.doc is None:
            return None
        return next((n for n in self.doc.blocks[key].nodes if isinstance(n, InsnNode) and n.addr == insn_addr), None)

    def get_selected_operand_info(self):
        """``(block key, insn addr, operand node)`` of the first selected operand, or None."""
        if not self.infodock.selected_operands or self.doc is None:
            return None
        ins_addr, operand_idx = next(iter(self.infodock.selected_operands))
        insn = self.insn_node(ins_addr)
        if insn is None:
            return None
        return self._insaddr_to_block[ins_addr], ins_addr, insn.get_operand(operand_idx)

    def update_label(self, addr: int, is_renaming: bool = False) -> None:  # pylint:disable=unused-argument
        """A label was renamed: make the blocks again (QDisassemblyGraph reloads the block), keeping the viewport."""
        self._layout()
        self._changed()

    def instruction_widget_rect(self, insn_addr: int):  # pylint:disable=unused-argument,no-self-use
        return None

    def node_at(self, x: int, y: int) -> tuple[Any, Any, int] | None:
        """``(block key, node, column into the line)`` under the layout cell ``(x, y)``, or None."""
        if self.doc is None:
            return None
        for key, (bx, by) in self.doc.layout.items():
            w, h = self.doc.sizes[key]
            if bx <= x < bx + w and by <= y < by + h:
                row = y - by - 1
                block = self.doc.blocks[key]
                lines = self.block_lines(block)
                if 0 <= row < len(lines) and len(lines) == len(block.lines):
                    return key, block.nodes[row], x - bx - 2
                return key, None, x - bx - 2
        return None

    def hide(self) -> None:
        self.visible = False

    def show(self) -> None:
        self.visible = True


class DetailOptions:
    """
    The display options a graph draws its blocks with at a level of detail: the presenter's, with comments hidden
    from level 1 and addresses from level 2. (The terminal has no zoom; these levels stand in for it.)
    """

    def __init__(self, presenter: DisasmPresenter, detail: int = 0) -> None:
        self.presenter = presenter
        self.detail = detail

    @property
    def show_address(self) -> bool:
        return self.presenter.show_address and self.detail < 2

    @property
    def show_comments(self) -> bool:
        return self.detail < 1

    @property
    def show_variable(self) -> bool:
        return self.presenter.show_variable

    @property
    def show_variable_identifier(self) -> bool:
        return self.presenter.show_variable_identifier


def _unique(nodes) -> list:
    out = []
    for node in nodes:
        if not out or out[-1] is not node:
            out.append(node)
    return out


class LinearControl:
    """
    The linear listing: a byte offset into the memory regions and a line into the first object shown, and the lines
    on screen.

    :param presenter:   The disassembly presenter.
    :param rows:        How many lines the viewport holds.
    :param on_change:   Called with no arguments when the frontend should draw again.
    """

    def __init__(self, presenter: DisasmPresenter, rows: int = 40, on_change: Callable[[], Any] | None = None):
        self.presenter = presenter
        self.rows = rows
        self.on_change = on_change
        self.offset: int | None = None
        self.start_line = 0
        self.shown: list[tuple[int, Any, int]] = []
        self.viewport_changed = Signal()
        self.visible = False
        self._disassembly_level = presenter.disassembly_level
        self.source = LinearSource(presenter)
        self._insaddr_to_block: dict[int, LinearBlock] = {}

    @property
    def infodock(self):
        return self.presenter.infodock

    @property
    def objects(self):
        """The display objects made so far, by address (QLinearDisassembly.objects)."""
        return self.source.objects

    @property
    def max_offset(self) -> int:
        return self.source.max_offset

    def _changed(self) -> None:
        if self.on_change is not None:
            self.on_change()

    def initialize(self) -> None:
        self.source.initialize()
        self.offset = None
        self.start_line = 0
        self.shown = []
        self._insaddr_to_block = {}

    def reload(self, old_infodock=None) -> None:  # pylint:disable=unused-argument
        offset = self.offset
        start = self.start_line
        self.initialize()
        self.prepare_objects(offset, start)
        self._changed()

    def refresh(self) -> None:
        self.prepare_objects(self.offset, self.start_line, force=True)
        self._changed()

    def redraw(self) -> None:
        self._changed()

    def refresh_objects(self) -> None:
        """Regenerate the objects of the viewport (new CFB objects arrived during CFG recovery)."""
        if self.offset is None:
            return
        self.prepare_objects(self.offset, self.start_line, force=True)
        self._changed()

    def set_disassembly_level(self, level) -> None:
        self._disassembly_level = level
        self.reload()

    def prepare_objects(self, offset: int | None, start_line: int = 0, force: bool = False) -> None:
        """Walk the blanket from ``offset``, ``start_line`` lines into the first object."""
        if offset is None:
            offset = 0
        if not force and offset == self.offset and start_line == self.start_line and self.shown:
            return
        source = self.source
        # CFG recovery may be adding to the functions shown: read them only while it stops for us
        with gate_of(self.presenter.instance).access() as granted:
            source.read_functions = granted
            try:
                shown, offset, start_line = source.objects_at(offset, self.rows, start_line)
            except (RuntimeError, KeyError, IndexError):
                # the CFB is being mutated by CFG recovery; keep what is shown, a later refresh retries
                return
            finally:
                source.read_functions = True
        self.offset, self.start_line, self.shown = offset, start_line, shown
        self._insaddr_to_block = {}
        for _addr, node, _first in shown:
            if isinstance(node, LinearBlock):
                for insn_addr in node.insn_addrs:
                    self._insaddr_to_block[insn_addr] = node
        self.viewport_changed.emit()

    def navigate_to_addr(self, addr: int) -> None:
        offset = self.source.offset_of_addr(addr)
        if offset is None:
            return
        self.navigate_to(offset)

    def navigate_to(self, offset: int) -> None:
        self.prepare_objects(offset, 0)
        self._changed()

    def scroll(self, lines: int) -> None:
        """Move the viewport by ``lines`` lines (negative: up)."""
        self.presenter.workspace.note_user_navigation()
        self.prepare_objects(self.offset, self.start_line + lines)
        self._changed()

    def show_instruction(  # pylint:disable=unused-argument
        self, insn_addr, insn_pos=None, centering: bool = False, use_block_pos: bool = False, use_animation=False
    ) -> None:
        if self.row_of(insn_addr) is not None:
            self._changed()
            return
        self.navigate_to_addr(insn_addr)

    def lines(self) -> list[tuple[Any, Line]]:
        """The viewport's lines, each with the node it belongs to."""
        out: list[tuple[Any, Line]] = []
        for _addr, node, first in self.shown:
            if isinstance(node, LinearBlock):
                node_lines = node.node_lines()
            else:
                node_lines = [(node, line) for line in self.presenter.node_lines(node, linear=True)]
            out.extend(node_lines[first:])
            if len(out) >= self.rows:
                break
        return out[: self.rows]

    def row_of(self, addr: int) -> int | None:
        """The viewport row of the instruction or label at ``addr``, or None if it is not on screen."""
        for row, (node, _line) in enumerate(self.lines()):
            if node is not None and getattr(node, "addr", None) == addr and isinstance(node, (InsnNode, LabelNode)):
                return row
        return None

    def visible_addr_range(self) -> tuple[int, int] | None:
        return self.source.visible_addr_range(self.offset, self.rows)

    @property
    def visible_function_addrs(self) -> list[int]:
        addrs: list[int] = []
        for block in self._insaddr_to_block.values():
            if block.func_addr not in addrs:
                addrs.append(block.func_addr)
        return addrs

    def function_addr_of_instruction(self, insn_addr: int) -> int | None:
        block = self._insaddr_to_block.get(insn_addr)
        return block.func_addr if block is not None else None

    @property
    def first_visible_instruction_addr(self) -> int | None:
        return next(iter(self._insaddr_to_block), None)

    @property
    def visible_memory_data(self) -> list:
        items = [(addr, node.memory_data) for addr, node, _first in self.shown if isinstance(node, MemoryDataNode)]
        items.sort(key=lambda item: item[0])
        return items

    def insn_node(self, insn_addr: int) -> InsnNode | None:
        """The node of the instruction at ``insn_addr`` in the blocks the listing has made, or None."""
        block = self._insaddr_to_block.get(insn_addr)
        if block is None:
            return None
        return next((n for n in block.nodes if isinstance(n, InsnNode) and n.addr == insn_addr), None)

    def get_selected_operand_info(self):
        if not self.presenter.infodock.selected_operands:
            return None
        ins_addr, operand_idx = next(iter(self.presenter.infodock.selected_operands))
        insn = self.insn_node(ins_addr)
        return None if insn is None else (self._insaddr_to_block[ins_addr], ins_addr, insn.get_operand(operand_idx))

    def instruction_widget_rect(self, insn_addr: int):  # pylint:disable=unused-argument,no-self-use
        return None

    def hide(self) -> None:
        self.visible = False

    def show(self) -> None:
        self.visible = True


class HeadlessDisasmView:
    """
    A disassembly view that draws nothing: a presenter and its two controls. Tests and scripts drive the presenter
    through it; ``open_menu`` records the menus the presenter opens.
    """

    def __init__(self, workspace, instance: Instance, rows: int = 40) -> None:
        self.workspace = workspace
        self.instance = instance
        self.presenter = DisasmPresenter(workspace, instance)
        self.presenter.view = self
        self.flow_graph = GraphControl(self.presenter)
        self.linear_viewer = LinearControl(self.presenter, rows=rows)
        self.opened_menus: list = []
        self.find_bar = FindBarState(DisasmPresenter.FIND_MODES)
        self.presenter.find_bar = self.find_bar
        self.find_bar.query_changed.connect(self.presenter.update_find_matches)
        self.find_bar.closed.connect(self.presenter.on_find_bar_closed)
        self.linear_viewer.viewport_changed.connect(self.presenter.on_linear_viewport_changed)
        # the display nodes call the presenter for jumps and menus
        self.presenter.attach(self, node_target=self.presenter)
        self.presenter.display_disasm_graph()

    def show_control(self, control) -> None:
        other = self.linear_viewer if control is self.flow_graph else self.flow_graph
        other.hide()
        control.show()

    def open_menu(self, menu) -> None:
        self.opened_menus.append(menu)

    default_docking_position = "center"

    @property
    def category(self) -> str:
        return "disassembly"

    @property
    def index(self) -> int:
        return self.presenter.index

    @index.setter
    def index(self, value: int) -> None:
        self.presenter.index = value

    @property
    def caption(self) -> str:
        return self.presenter.caption

    def jump_to(self, addr: int, *args, **kwargs) -> bool:
        return self.presenter.jump_to(addr, *args, **kwargs)

    def on_focused(self) -> None:
        self.presenter.on_focused()

    def close(self) -> None:
        self.presenter.close()


__all__ = ["DetailOptions", "GraphControl", "HeadlessDisasmView", "LinearControl"]
