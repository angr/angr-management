"""
The feature map strip of the terminal frontend: one row across the window, a cell per slice of the memory space,
coloured by what the slice holds (code, data, strings, or nothing known) as the Qt feature map paints it. A region
starts at a ``▏`` in the delimiter colour; ``▼`` marks the cursors of the view the user works in. A click (or a drag)
shows that address in the view the user worked in last, and the tooltip says what is under the mouse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.color import Color as RichColor
from rich.segment import Segment
from rich.style import Style
from textual.strip import Strip
from textual.widget import Widget

from angrmanagement.present.feature_map import (
    DELIMITER_COLOR,
    FEATURE_TAG_COLORS,
    UNKNOWN_COLOR,
    FeatureMapPresenter,
    tag_color,
)
from angrmanagement.tui.theme import rich_color
from angrmanagement.tui.widgets.styles import current_theme

if TYPE_CHECKING:
    from textual import events

    from angrmanagement.config.color import Color

DELIMITER = "▏"
CURSOR = "▼"
#: The cursor's colour, Qt.GlobalColor.yellow in the Qt feature map.
CURSOR_COLOR = RichColor.from_rgb(0xFF, 0xFF, 0x00)


class FeatureMapStrip(Widget):
    """The feature map of the main instance, one row high."""

    DEFAULT_CSS = """
    FeatureMapStrip {
        height: 1;
        width: 1fr;
    }
    """

    def __init__(self, workspace, *, id: str | None = None) -> None:  # pylint: disable=redefined-builtin
        super().__init__(id=id)
        self.presenter = FeatureMapPresenter(workspace)
        self.presenter.on_changed = self.relayout
        self.presenter.on_cursors_changed = self._drop_cells
        self._cells: list[Segment] | None = None
        self._dragging = False

    def on_unmount(self) -> None:
        self.presenter.close()

    def on_resize(self, _event: events.Resize) -> None:
        self.relayout()

    def relayout(self) -> None:
        """The maps or the width changed: lay the regions out again."""
        self.presenter.model.layout(max(self.size.width, 1))
        self._drop_cells()

    def _drop_cells(self) -> None:
        self._cells = None
        self.refresh()

    #
    # Drawing
    #

    def cells(self) -> list[Segment]:
        """A segment per cell: its colour, a region's start or a cursor."""
        if self._cells is None:
            self._cells = self._build_cells()
        return self._cells

    def _build_cells(self) -> list[Segment]:
        theme = current_theme(self)
        colors: list[Color] = [theme.color(name) or theme.foreground for name in FEATURE_TAG_COLORS]
        unknown = theme.color(UNKNOWN_COLOR) or theme.background
        delimiter = rich_color(theme.color(DELIMITER_COLOR) or theme.foreground)
        model = self.presenter.model
        width = self.size.width
        starts = {round(model.region_span(mr)[0]) for mr in model.regions_between(0, width)}
        cursor_cells = set()
        for addr in self.presenter.cursors:
            pos = model.position_at_addr(addr)
            if pos is not None:
                cursor_cells.add(min(int(pos), width - 1))
        out = []
        for x in range(width):
            mr = model.region_at_position(x + 0.5)
            color = unknown
            if mr is not None:
                lo, hi = model.addr_at_position(x), model.addr_at_position(x + 1)
                if lo is not None and hi is not None:
                    tags = model.tags_between(mr, lo, max(lo, hi - 1))
                    if tags:
                        color = tag_color(colors, tags)
            background = rich_color(color)
            if x in cursor_cells:
                out.append(Segment(CURSOR, Style(color=CURSOR_COLOR, bgcolor=background, bold=True)))
            elif x in starts and x > 0:
                out.append(Segment(DELIMITER, Style(color=delimiter, bgcolor=background)))
            else:
                out.append(Segment(" ", Style(bgcolor=background)))
        return out

    def render_line(self, y: int) -> Strip:
        if y != 0:
            return Strip.blank(self.size.width)
        return Strip(self.cells(), self.size.width)

    #
    # The mouse
    #

    def on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 1:
            self._dragging = True
            self.capture_mouse()
            self.presenter.select_at_position(event.x + 0.5)

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._dragging:
            self._dragging = False
            self.release_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        if self._dragging:
            self.presenter.select_at_position(event.x + 0.5)
        self.tooltip = self.presenter.model.tooltip_at(event.x + 0.5) or None


__all__ = ["FeatureMapStrip"]
