"""
The feature map strip of the terminal frontend: one row across the window, a cell per slice of the memory space,
coloured by what the slice holds (code, data, strings, or nothing known) as the Qt feature map paints it. A region
starts at a ``▏`` in the delimiter colour; ``▼`` marks the cursors of the view the user works in. A click (or a drag)
shows that address in the view the user worked in last, and the tooltip says what is under the mouse.

On a tier 3 terminal a picture of the strip lies over the cells, eight slices a cell instead of one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.color import Color as RichColor
from rich.segment import Segment
from rich.style import Style
from textual.strip import Strip
from textual.widget import Widget

from angrmanagement.config.color import Color
from angrmanagement.present.feature_map import (
    DELIMITER_COLOR,
    FEATURE_TAG_COLORS,
    UNKNOWN_COLOR,
    FeatureMapPresenter,
    tag_color,
)
from angrmanagement.tui.pictures import PIXELS_PER_CELL, columns_image, placeholder
from angrmanagement.tui.theme import rich_color
from angrmanagement.tui.widgets.picture import graphics_tier, image_module, set_picture
from angrmanagement.tui.widgets.styles import current_theme

if TYPE_CHECKING:
    from textual import events
    from textual.app import ComposeResult

DELIMITER = "▏"
CURSOR = "▼"
#: The cursor's colour, Qt.GlobalColor.yellow in the Qt feature map.
CURSOR_COLOR = RichColor.from_rgb(0xFF, 0xFF, 0x00)
PICTURE_CURSOR_COLOR = Color(0xFF, 0xFF, 0x00)


class FeatureMapStrip(Widget):
    """The feature map of the main instance, one row high."""

    DEFAULT_CSS = """
    FeatureMapStrip {
        height: 1;
        width: 1fr;
    }
    FeatureMapStrip #feature-map-picture {
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
        #: the picture of the strip on a tier 3 terminal, None on any other
        self.picture: Widget | None = None

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
        if self.picture is not None and self.size.width:
            set_picture(self.picture, self.picture_image())

    def compose(self) -> ComposeResult:
        # a tier 3 terminal shows the strip as a picture over the cells
        if graphics_tier(getattr(self.app, "caps", None)):
            self.picture = image_module().Image(placeholder(), id="feature-map-picture")
            yield self.picture

    #
    # Drawing
    #

    def cells(self) -> list[Segment]:
        """A segment per cell: its colour, a region's start or a cursor."""
        if self._cells is None:
            self._cells = self._build_cells()
        return self._cells

    def slice_colors(self, scale: int = 1) -> list[tuple[Color, str]]:
        """
        The colour of each of ``scale`` slices a cell, across the strip, and what the slice is: ``""``, ``"start"``
        (a region starts there) or ``"cursor"``.
        """
        theme = current_theme(self)
        colors: list[Color] = [theme.color(name) or theme.foreground for name in FEATURE_TAG_COLORS]
        unknown = theme.color(UNKNOWN_COLOR) or theme.background
        model = self.presenter.model
        width = self.size.width
        count = width * scale
        starts = {round(model.region_span(mr)[0] * scale) for mr in model.regions_between(0, width)}
        cursor_slices = set()
        for addr in self.presenter.cursors:
            pos = model.position_at_addr(addr)
            if pos is not None:
                cursor_slices.add(min(int(pos * scale), count - 1))
        out = []
        for x in range(count):
            mr = model.region_at_position((x + 0.5) / scale)
            color = unknown
            if mr is not None:
                lo, hi = model.addr_at_position(x / scale), model.addr_at_position((x + 1) / scale)
                if lo is not None and hi is not None:
                    tags = model.tags_between(mr, lo, max(lo, hi - 1))
                    if tags:
                        color = tag_color(colors, tags)
            kind = "cursor" if x in cursor_slices else ("start" if x in starts and x > 0 else "")
            out.append((color, kind))
        return out

    def _build_cells(self) -> list[Segment]:
        theme = current_theme(self)
        delimiter = rich_color(theme.color(DELIMITER_COLOR) or theme.foreground)
        out = []
        for color, kind in self.slice_colors():
            background = rich_color(color)
            if kind == "cursor":
                out.append(Segment(CURSOR, Style(color=CURSOR_COLOR, bgcolor=background, bold=True)))
            elif kind == "start":
                out.append(Segment(DELIMITER, Style(color=delimiter, bgcolor=background)))
            else:
                out.append(Segment(" ", Style(bgcolor=background)))
        return out

    def picture_image(self) -> Any:
        """The strip as a picture, :data:`PIXELS_PER_CELL` pixels a cell: the delimiters and cursors one pixel wide."""
        theme = current_theme(self)
        delimiter = theme.color(DELIMITER_COLOR) or theme.foreground
        marks = {"cursor": PICTURE_CURSOR_COLOR, "start": delimiter}
        colors = [marks.get(kind, color) for color, kind in self.slice_colors(PIXELS_PER_CELL[0])]
        return columns_image(colors, PIXELS_PER_CELL[1])

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
            self.presenter.select_at_position(self._local_x(event) + 0.5)

    def _local_x(self, event: events.MouseEvent) -> float:
        """The column of ``event`` in the strip, also when it comes up from the picture."""
        return event.screen_x - self.region.x

    def on_mouse_up(self, _event: events.MouseUp) -> None:
        if self._dragging:
            self._dragging = False
            self.release_mouse()

    def on_mouse_move(self, event: events.MouseMove) -> None:
        x = self._local_x(event)
        if self._dragging:
            self.presenter.select_at_position(x + 0.5)
        self.tooltip = self.presenter.model.tooltip_at(x + 0.5) or None


__all__ = ["FeatureMapStrip"]
