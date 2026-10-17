"""
The trace viewer's strip for the terminal's disassembly view: what the Qt QTraceViewer draws beside the graph, a row
per slice of the trace with the legend's colour, the function's colour and its name where the function changes, and
the positions of the selected instruction marked. A click on a row, or Up and Down, goes to that point of the trace.
H switches to the heat map of every trace and back, as the Qt strip's MultiTrace HeatMap tab does: the plugin's block
colours and instruction marks show only then.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from rich.segment import Segment
from rich.style import Style
from textual.binding import Binding
from textual.strip import Strip
from textual.widget import Widget

from angrmanagement.config.color import Color

if TYPE_CHECKING:
    from textual import events

#: the Qt legend's gradient: position in the trace (0 to 1) and colour
LEGEND_STOPS = (
    (0.0, Color(255, 0, 0)),
    (0.4, Color(255, 255, 0)),
    (0.6, Color(0, 255, 0)),
    (0.8, Color(0, 0, 255)),
    (1.0, Color(0, 0, 128)),
)


def legend_color(position: int, total: int) -> Color:
    """The legend's colour at ``position`` of ``total``, as the Qt strip reads it from its gradient."""
    t = position / max(1, total - 1) if total > 1 else 0.0
    for (t0, c0), (t1, c1) in zip(LEGEND_STOPS, LEGEND_STOPS[1:], strict=False):
        if t <= t1:
            f = (t - t0) / (t1 - t0) if t1 > t0 else 0.0
            return Color(*(round(a + (b - a) * f) for a, b in ((c0.r, c1.r), (c0.g, c1.g), (c0.b, c1.b))))
    return LEGEND_STOPS[-1][1]


def _rich(color: Color) -> str:
    return f"#{color.rgb_hex}"


class TraceStrip(Widget, can_focus=True):
    """The trace beside the disassembly; hidden while there is no trace."""

    DEFAULT_CSS = """
    TraceStrip {
        width: 32;
        height: 1fr;
        border-left: vkey $primary 40%;
    }
    """
    BINDINGS: ClassVar = [
        Binding("up", "move(-1)", "Earlier in the trace", show=False),
        Binding("down", "move(1)", "Later in the trace", show=False),
        Binding("h", "heatmap", "Heat map of every trace", show=False),
    ]

    def __init__(self, workspace: Any, disasm_view: Any) -> None:
        super().__init__()
        self.workspace = workspace
        self.disasm_view = disasm_view
        #: the position in the trace shown as current
        self.position = 0
        self.display = False
        self.trace.am_subscribe(self._on_trace)
        self.selected_ins.am_subscribe(self._on_select)

    @property
    def trace(self) -> Any:
        return self.workspace.main_instance.trace

    @property
    def selected_ins(self) -> Any:
        return self.disasm_view.infodock.selected_insns

    def on_unmount(self) -> None:
        self.trace.am_unsubscribe(self._on_trace)
        self.selected_ins.am_unsubscribe(self._on_select)

    #
    # The trace
    #

    def _on_trace(self, **_kwargs) -> None:
        self.refresh_trace()

    def refresh_trace(self) -> None:
        """Show the current trace, and give its positions the legend's colours, as the Qt strip does."""
        trace = self.trace
        shown = not trace.am_none and bool(trace.count)
        self.display = shown
        if shown:
            for p in range(trace.count):
                trace.set_mark_color(p, legend_color(p, trace.count))
            self.position = min(self.position, trace.count - 1)
        self.refresh()

    def _on_select(self, **_kwargs) -> None:
        if not self.trace.am_none and self.selected_ins:
            positions = self.trace.get_positions(next(iter(self.selected_ins)))
            if positions:
                self.position = positions[0]
        self.refresh()

    def rows(self) -> int:
        """The rows the trace takes: one per position, or the strip's height when the trace is longer."""
        height = max(1, self.size.height - 1)
        count = self.trace.count or 0
        return min(count, height)

    def positions_of_row(self, row: int) -> range:
        count = self.trace.count or 0
        rows = self.rows()
        return range(row * count // rows, max(row * count // rows + 1, (row + 1) * count // rows))

    def row_of_position(self, position: int) -> int:
        count = self.trace.count or 1
        return min(self.rows() - 1, position * self.rows() // count)

    #
    # Drawing
    #

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        trace = self.trace
        if trace.am_none or not trace.count:
            return Strip.blank(width)
        if y == 0:
            heatmap = not self.multi_trace.am_none and getattr(self.multi_trace, "is_active_tab", False)
            title = f" Trace {trace.id} ({trace.count}){' heat map' if heatmap else ''}"[:width]
            return Strip([Segment(title.ljust(width), Style(bold=True))])
        row = y - 1
        if row >= self.rows():
            return Strip.blank(width)
        positions = self.positions_of_row(row)
        first = positions.start
        item = trace.trace_func[first]
        selected = set()
        if self.selected_ins:
            selected = set(trace.get_positions(next(iter(self.selected_ins))))
        marked = any(p in selected for p in positions)
        current = self.position in positions
        legend = Style(bgcolor=_rich(legend_color(first, trace.count)))
        func_style = Style(bgcolor=_rich(trace.get_func_color(item.func_name)))
        previous = trace.trace_func[self.positions_of_row(row - 1).start].func_name if row > 0 else None
        name = item.func_name if item.func_name != previous else ""
        label_style = Style(reverse=True) if marked else Style()
        if current:
            label_style += Style(bold=True)
        mark = "▶" if current else ("•" if marked else " ")
        text = f"{mark}{name}"[: max(0, width - 4)]
        return Strip(
            [
                Segment(" ", legend),
                Segment("  ", func_style),
                Segment(" ", Style()),
                Segment(text.ljust(max(0, width - 4)), label_style),
            ]
        )

    #
    # Going to a point of the trace
    #

    def go_to(self, position: int) -> None:
        """Show the trace's block at ``position`` in the disassembly, as a click on the Qt strip does."""
        trace = self.trace
        if trace.am_none or not trace.count:
            return
        self.position = max(0, min(trace.count - 1, position))
        func = trace.get_func_from_position(self.position)
        bbl_addr = trace.get_bbl_from_position(self.position)
        if func is None:
            self.refresh()
            return
        self.workspace.on_function_selected(func)
        insn_addrs = self.workspace.main_instance.project.factory.block(bbl_addr).instruction_addrs
        self.selected_ins.clear()
        self.selected_ins.update(insn_addrs)
        self.selected_ins.am_event()
        self.disasm_view.jump_to(bbl_addr)
        self.refresh()

    @property
    def multi_trace(self) -> Any:
        return self.workspace.main_instance.multi_trace

    def action_heatmap(self) -> None:
        """The heat map of every loaded trace, or back to the single trace, as switching the Qt strip's tabs does."""
        multi = self.multi_trace
        if multi.am_none or not hasattr(multi.am_obj, "reload_heatmap"):
            return
        if multi.is_active_tab:
            multi.is_active_tab = False
        else:
            multi.clear_heatmap()
            multi.is_active_tab = True
            multi.reload_heatmap(multi.get_all_trace_ids())
        multi.am_event()
        self.refresh()

    def on_click(self, event: events.Click) -> None:
        if event.y >= 1 and not self.trace.am_none and self.trace.count:
            row = event.y - 1
            if row < self.rows():
                self.go_to(self.positions_of_row(row).start)

    def action_move(self, delta: int) -> None:
        self.go_to(self.position + delta)


__all__ = ["LEGEND_STOPS", "TraceStrip", "legend_color"]
