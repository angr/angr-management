"""
The trace map of the terminal frontend: a strip over the trace's events, one column per range of events, with the
replay position (a yellow line with arrows at its ends, red shading before it and blue after, as the Qt map's
gradients), the checkpoints in green and the event under the mouse in grey. A click or a drag replays the trace to
the event under the mouse; Left and Right move the replay by one column.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.segment import Segment
from rich.style import Style
from textual.strip import Strip
from textual.widget import Widget

from angrmanagement.config.color import Color
from angrmanagement.present.trace_map import TraceMapPresenter, pos_from_addr
from angrmanagement.tui.theme import rich_color
from angrmanagement.tui.widgets.styles import blend, current_theme

from .base import TuiView

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

#: The colours of the Qt map: the replay position, the shading before and after it, checkpoints and the mouse.
CURRENT_COLOR = Color(0xFF, 0xFF, 0x00)
BEFORE_COLOR = Color(0xFF, 0x00, 0x00)
AFTER_COLOR = Color(0x00, 0x00, 0xFF)
CHECKPOINT_COLOR = Color(0x00, 0xFF, 0x00)
HOVER_COLOR = Color(0xA0, 0xA0, 0xA4)
#: The strongest shading, next to the replay position.
FRONTIER_ALPHA = 0.7


class TraceMapWidget(Widget, can_focus=True):
    """The strip: every line shows the same columns; the first and last lines carry the markers' arrow heads."""

    DEFAULT_CSS = """
    TraceMapWidget {
        height: 1fr;
        width: 1fr;
    }
    """

    def __init__(self, view: TraceMapTuiView) -> None:
        super().__init__()
        self.view = view
        self._dragging = False

    @property
    def presenter(self) -> TraceMapPresenter:
        return self.view.presenter

    def column_styles(self, width: int) -> list[tuple[str, Style]]:
        """The character and style of each column for a middle line."""
        base = current_theme(self).background
        cells: list[tuple[str, Style]] = [(" ", Style(bgcolor=rich_color(base)))] * width
        for start, end, kind in self.presenter.model.segments(width):
            for x in range(max(start, 0), min(end, width)):
                if kind in ("frontier_before", "frontier_after"):
                    span = max(end - start, 1)
                    # strongest next to the replay position, fading away from it
                    near = (x - start + 1) / span if kind == "frontier_before" else (end - x) / span
                    color = BEFORE_COLOR if kind == "frontier_before" else AFTER_COLOR
                    cells[x] = (" ", Style(bgcolor=rich_color(blend(color, base, FRONTIER_ALPHA * near))))
                else:
                    color = {"checkpoint": CHECKPOINT_COLOR, "current": CURRENT_COLOR, "hover": HOVER_COLOR}[kind]
                    bg = cells[x][1].bgcolor
                    cells[x] = ("│", Style(color=rich_color(color), bgcolor=bg, bold=kind == "current"))
        return cells

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        height = self.size.height
        cells = self.column_styles(width)
        model = self.presenter.model
        markers = {}
        for addr, kind in [(c, "checkpoint") for c in model.checkpoints] + [(model.addr, "current")]:
            pos = pos_from_addr(addr, model.total, width)
            if pos is not None:
                markers[min(pos, width - 1)] = kind
        if height > 1 and y in (0, height - 1):
            arrow = "▼" if y == 0 else "▲"
            for x in markers:
                char, style = cells[x]
                if char == "│":
                    cells[x] = (arrow, style)
        return Strip([Segment(char, style) for char, style in cells], width)

    def _pos(self, event: events.MouseEvent) -> int:
        return max(0, min(int(event.x), self.size.width - 1))

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 1:
            self.presenter.select_offset(self._pos(event), self.size.width)
            self._dragging = True
            self.capture_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._dragging:
            self.presenter.select_offset(self._pos(event), self.size.width)
            return
        self.presenter.hover(self._pos(event), self.size.width)
        self.refresh()

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._dragging:
            self._dragging = False
            self.release_mouse()

    def on_leave(self, _event: events.Leave) -> None:
        self.presenter.hover(None, self.size.width)
        self.refresh()

    def on_key(self, event: events.Key) -> None:
        if event.key not in ("left", "right"):
            return
        event.stop()
        width = self.size.width
        model = self.presenter.model
        pos = pos_from_addr(model.addr, model.total, width)
        if pos is not None:
            self.presenter.select_offset(max(0, min(pos + (1 if event.key == "right" else -1), width - 1)), width)


class TraceMapTuiView(TuiView):
    """The trace map."""

    PRESENTER_CLASS = TraceMapPresenter

    presenter: TraceMapPresenter

    def __init__(self, workspace, default_docking_position: str, instance) -> None:
        super().__init__(workspace, default_docking_position, instance)
        self.map = TraceMapWidget(self)
        self.presenter.on_changed = self.map_changed

    def compose(self) -> ComposeResult:
        yield self.map

    def map_changed(self) -> None:
        if self.is_attached:
            self.map.refresh()

    def focus_view(self) -> None:
        self.map.focus()


__all__ = ["TraceMapTuiView", "TraceMapWidget"]
