"""
A grid of character cells with styles, for drawing graphs in a terminal.

:class:`CharCanvas` holds one character and one style key per cell. Text goes in with :meth:`CharCanvas.text` and
:meth:`CharCanvas.blit`; lines go in as directions per cell (:meth:`CharCanvas.hline`, :meth:`CharCanvas.vline`,
:meth:`CharCanvas.polyline`, :meth:`CharCanvas.box`), so lines that meet merge into the right box-drawing character
(``┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼``) and crossings become ``┼``. :meth:`CharCanvas.to_strips` turns a window of the canvas into
Textual strips, styling each run of cells through a function from style keys to Rich styles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.segment import Segment
from rich.style import Style
from textual.strip import Strip

from angrmanagement.present.links import disasm_link_addr, with_link

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from angrmanagement.present.spans import Line

UP = 1
DOWN = 2
LEFT = 4
RIGHT = 8

#: The box-drawing character of each set of directions a cell's lines go in.
GLYPHS = {
    0: " ",
    UP: "│",
    DOWN: "│",
    UP | DOWN: "│",
    LEFT: "─",
    RIGHT: "─",
    LEFT | RIGHT: "─",
    DOWN | RIGHT: "┌",
    DOWN | LEFT: "┐",
    UP | RIGHT: "└",
    UP | LEFT: "┘",
    UP | DOWN | RIGHT: "├",
    UP | DOWN | LEFT: "┤",
    DOWN | LEFT | RIGHT: "┬",
    UP | LEFT | RIGHT: "┴",
    UP | DOWN | LEFT | RIGHT: "┼",
}

#: The arrow head that ends a line going in a direction.
ARROWS = {DOWN: "▼", UP: "▲", LEFT: "◀", RIGHT: "▶"}


def _direction(a: tuple[int, int], b: tuple[int, int]) -> int:
    (ax, ay), (bx, by) = a, b
    if bx == ax:
        return DOWN if by > ay else UP if by < ay else 0
    if by == ay:
        return RIGHT if bx > ax else LEFT
    raise ValueError(f"not an orthogonal segment: {a} -> {b}")


class CharCanvas:
    """
    A ``width`` by ``height`` grid of cells; each has a character, a style key, and the directions of the lines
    through it.
    """

    def __init__(self, width: int, height: int, style: str = "") -> None:
        self.width = max(width, 0)
        self.height = max(height, 0)
        self.default_style = style
        self.chars = [[" "] * self.width for _ in range(self.height)]
        self.styles = [[style] * self.width for _ in range(self.height)]
        self.bits = [[0] * self.width for _ in range(self.height)]
        #: cells whose character is text, which lines do not overwrite
        self._text = [[False] * self.width for _ in range(self.height)]

    def inside(self, x: int, y: int) -> bool:
        return 0 <= x < self.width and 0 <= y < self.height

    #
    # Text
    #

    def put(self, x: int, y: int, char: str, style: str | None = None) -> None:
        """Write one character (text: lines drawn later do not cover it)."""
        if self.inside(x, y):
            self.chars[y][x] = char
            if style is not None:
                self.styles[y][x] = style
            self._text[y][x] = True

    def text(self, x: int, y: int, text: str, style: str | None = None) -> int:
        """Write ``text`` from ``(x, y)`` to the right; returns the column after it."""
        for i, char in enumerate(text):
            self.put(x + i, y, char, style)
        return x + len(text)

    def fill(self, x: int, y: int, width: int, height: int, style: str, char: str | None = None) -> None:
        """Give a rectangle a style (a background), and a character if given; text already there keeps its own."""
        for row in range(y, y + height):
            for col in range(x, x + width):
                if not self.inside(col, row):
                    continue
                if char is not None and not self._text[row][col]:
                    self.chars[row][col] = char
                self.styles[row][col] = style

    def clear(self, x: int, y: int, width: int, height: int, style: str | None = None) -> None:
        """Empty a rectangle: no text, no lines, ``style`` (the canvas's own by default)."""
        style = self.default_style if style is None else style
        for row in range(y, y + height):
            for col in range(x, x + width):
                if self.inside(col, row):
                    self.chars[row][col] = " "
                    self.styles[row][col] = style
                    self.bits[row][col] = 0
                    self._text[row][col] = False

    def blit(self, lines: Iterable[Line], x: int, y: int, base_style: str = "", width: int | None = None) -> None:
        """
        Write lines of spans from ``(x, y)`` down. Each span's style is laid over ``base_style``; ``width`` pads
        every line with ``base_style`` to that many cells.
        """
        for row, line in enumerate(lines):
            col = x
            for span in line.spans:
                # an address of the disassembly links to its angr:// URL (angrmanagement.present.links)
                style = with_link(f"{base_style} {span.style}".strip(), disasm_link_addr(span))
                col = self.text(col, y + row, span.text, style)
            if width is not None:
                for pad in range(col, x + width):
                    self.put(pad, y + row, " ", base_style)

    #
    # Lines
    #

    def _add(self, x: int, y: int, bits: int, style: str | None) -> None:
        if not self.inside(x, y) or self._text[y][x]:
            return
        self.bits[y][x] |= bits
        self.chars[y][x] = GLYPHS[self.bits[y][x]]
        if style is not None:
            self.styles[y][x] = style

    def hline(self, x0: int, x1: int, y: int, style: str | None = None) -> None:
        """A horizontal line from column ``x0`` to ``x1``, both included."""
        if x0 > x1:
            x0, x1 = x1, x0
        for x in range(x0, x1 + 1):
            bits = (LEFT if x > x0 else 0) | (RIGHT if x < x1 else 0)
            self._add(x, y, bits or LEFT | RIGHT, style)

    def vline(self, x: int, y0: int, y1: int, style: str | None = None) -> None:
        """A vertical line from row ``y0`` to ``y1``, both included."""
        if y0 > y1:
            y0, y1 = y1, y0
        for y in range(y0, y1 + 1):
            bits = (UP if y > y0 else 0) | (DOWN if y < y1 else 0)
            self._add(x, y, bits or UP | DOWN, style)

    def polyline(self, points: Sequence[tuple[int, int]], style: str | None = None, arrow: bool = True) -> None:
        """
        Orthogonal segments through ``points``, merging at the corners, with an arrow head on the last point (in the
        direction of the last segment) when ``arrow`` is set.
        """
        points = [p for i, p in enumerate(points) if i == 0 or p != points[i - 1]]
        if len(points) < 2:
            return
        for a, b in zip(points, points[1:], strict=False):
            d = _direction(a, b)
            back = {DOWN: UP, UP: DOWN, LEFT: RIGHT, RIGHT: LEFT}[d]
            (ax, ay), (bx, by) = a, b
            self._add(ax, ay, d, style)
            step_x = (bx > ax) - (bx < ax)
            step_y = (by > ay) - (by < ay)
            x, y = ax + step_x, ay + step_y
            while (x, y) != (bx, by):
                self._add(x, y, d | back, style)
                x, y = x + step_x, y + step_y
            self._add(bx, by, back, style)
        if arrow:
            end = points[-1]
            d = _direction(points[-2], end)
            ex, ey = end
            if self.inside(ex, ey) and not self._text[ey][ex]:
                self.chars[ey][ex] = ARROWS[d]
                if style is not None:
                    self.styles[ey][ex] = style

    def mark(self, x: int, y: int, bits: int, style: str | None = None) -> None:
        """Add line directions to one cell, as where an edge leaves a box's border."""
        self._add(x, y, bits, style)

    def box(self, x: int, y: int, width: int, height: int, title: str | None = None, style: str | None = None) -> None:
        """A rectangle's border, ``width`` by ``height`` cells including it, with ``title`` in its top edge."""
        if width < 2 or height < 2:
            return
        right, bottom = x + width - 1, y + height - 1
        self.hline(x, right, y, style)
        self.hline(x, right, bottom, style)
        self.vline(x, y, bottom, style)
        self.vline(right, y, bottom, style)
        if title:
            self.text(x + 2, y, f" {title} "[: max(width - 4, 0)], style)

    #
    # Output
    #

    def row_text(self, y: int) -> str:
        return "".join(self.chars[y]) if 0 <= y < self.height else ""

    def __str__(self) -> str:
        return "\n".join(self.row_text(y) for y in range(self.height))

    def strip(self, y: int, style_of: Callable[[str], Style], x0: int = 0, width: int | None = None) -> Strip:
        """Row ``y`` from column ``x0``, ``width`` cells wide (padded past the edge), as a Strip."""
        width = self.width - x0 if width is None else width
        blank = style_of(self.default_style)
        if not 0 <= y < self.height:
            return Strip.blank(width, blank)
        segments: list[Segment] = []
        if x0 < 0:
            # columns left of the canvas are blank
            lead = min(-x0, width)
            segments.append(Segment(" " * lead, blank))
            width -= lead
            x0 = 0
            if width <= 0:
                return Strip(segments, lead)
            rest = self.strip(y, style_of, x0, width)
            return Strip([*segments, *rest], lead + width)
        run: list[str] = []
        run_style: str | None = None
        end = min(x0 + width, self.width)
        for x in range(max(x0, 0), end):
            style = self.styles[y][x]
            if style != run_style and run:
                segments.append(Segment("".join(run), style_of(run_style or "")))
                run = []
            run_style = style
            run.append(self.chars[y][x])
        if run:
            segments.append(Segment("".join(run), style_of(run_style or "")))
        shown = max(end - max(x0, 0), 0)
        if shown < width:
            segments.append(Segment(" " * (width - shown), blank))
        return Strip(segments, width)

    def to_strips(
        self, viewport: tuple[int, int, int, int] | None = None, style_of: Callable[[str], Style] | None = None
    ) -> list[Strip]:
        """
        The cells in ``viewport`` (``x, y, width, height``; the whole canvas by default) as one Strip per row.

        :param style_of:    The Rich style of a style key; plain text by default.
        """
        x, y, width, height = viewport if viewport is not None else (0, 0, self.width, self.height)
        resolve = style_of if style_of is not None else (lambda _key: Style.null())
        return [self.strip(row, resolve, x, width) for row in range(y, y + height)]


__all__ = ["ARROWS", "DOWN", "GLYPHS", "LEFT", "RIGHT", "UP", "CharCanvas"]
