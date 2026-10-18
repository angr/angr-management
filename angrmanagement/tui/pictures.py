"""
The pictures a tier 3 terminal shows in place of the text drawings: the graph's minimap, the feature map, the trace
map and the preview of an exported image, as PIL images for :mod:`angrmanagement.tui.widgets.picture`.

Each map is drawn at :data:`PIXELS_PER_CELL` pixels a cell, so a picture shows what the text drawing has to round to
whole cells (or to braille dots): a one pixel line for the trace map's replay position, as the Qt map draws it. PIL
comes with textual-image, which is the only reason these are drawn; nothing here is imported below tier 3.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angrmanagement.config.color import Color

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from PIL.Image import Image
    from rich.style import Style

#: How many pixels across and down one terminal cell is drawn with.
PIXELS_PER_CELL = (8, 16)
#: Braille dots across and down one cell.
BRAILLE_DOTS = (2, 4)
_BRAILLE_BITS = ((0x01, 0x08), (0x02, 0x10), (0x04, 0x20), (0x40, 0x80))
BLACK = Color(0, 0, 0)


def rgb(color: Color) -> tuple[int, int, int]:
    return color.r, color.g, color.b


def new_image(width: int, height: int, background: Color) -> Image:
    from PIL import Image as PilImage  # pylint:disable=import-outside-toplevel

    return PilImage.new("RGB", (max(width, 1), max(height, 1)), rgb(background))


def placeholder(background: Color = BLACK) -> Image:
    """A one-pixel picture, for an image widget whose picture is drawn once it has a size."""
    return new_image(1, 1, background)


def columns_image(colors: Sequence[Color], height: int) -> Image:
    """A picture ``height`` pixels high with one pixel column per colour."""
    from PIL import ImageDraw  # pylint:disable=import-outside-toplevel

    image = new_image(len(colors), height, colors[0] if colors else BLACK)
    draw = ImageDraw.Draw(image)
    for x, color in enumerate(colors):
        draw.line([(x, 0), (x, height - 1)], fill=rgb(color))
    return image


def minimap_image(
    layout: Iterable[tuple[int, int, int, int]],
    viewport: tuple[int, int, int, int],
    cells: tuple[int, int],
    cell_scale: tuple[float, float],
    colors: tuple[Color, Color, Color],
) -> Image:
    """
    The graph's minimap ``cells`` cells large, a cell standing for ``cell_scale`` layout cells as in the braille
    minimap: each block (``x, y, width, height`` in layout cells) filled, and the viewport's outline, over the
    background. ``colors`` are the background, the blocks and the viewport.
    """
    from PIL import ImageDraw  # pylint:disable=import-outside-toplevel

    background, block, view = colors
    fx, fy = PIXELS_PER_CELL[0] / cell_scale[0], PIXELS_PER_CELL[1] / cell_scale[1]
    image = new_image(cells[0] * PIXELS_PER_CELL[0], cells[1] * PIXELS_PER_CELL[1], background)
    draw = ImageDraw.Draw(image)
    for x, y, w, h in layout:
        draw.rectangle([x * fx, y * fy, max((x + w) * fx - 1, x * fx), max((y + h) * fy - 1, y * fy)], fill=rgb(block))
    vx, vy, vw, vh = viewport
    draw.rectangle([vx * fx, vy * fy, (vx + vw) * fx - 1, (vy + vh) * fy - 1], outline=rgb(view), width=2)
    return image


def style_color(style: Style | None, foreground: bool, default: Color) -> Color:
    """The colour of a Rich style's foreground or background, or ``default``."""
    color = None if style is None else (style.color if foreground else style.bgcolor)
    if color is None:
        return default
    triplet = color.get_truecolor()
    return Color(triplet.red, triplet.green, triplet.blue)


def strips_image(strips: Sequence[Any], background: Color, cell: tuple[int, int] = (3, 6)) -> Image:
    """
    A picture of text, ``cell`` pixels a character: each cell its background, and a character's foreground as a bar
    across the middle of its cell, as a page of text looks from a distance.
    """
    from PIL import ImageDraw  # pylint:disable=import-outside-toplevel

    width = max((strip.cell_length for strip in strips), default=1)
    image = new_image(width * cell[0], max(len(strips), 1) * cell[1], background)
    draw = ImageDraw.Draw(image)
    for row, strip in enumerate(strips):
        x = 0
        for segment in strip:
            text, style = segment.text, segment.style
            bg = style_color(style, False, background)
            fg = style_color(style, True, Color(0xC0, 0xC0, 0xC0))
            for char in text:
                left, top = x * cell[0], row * cell[1]
                if bg != background:
                    draw.rectangle([left, top, left + cell[0] - 1, top + cell[1] - 1], fill=rgb(bg))
                if not char.isspace():
                    draw.rectangle([left, top + cell[1] // 3, left + cell[0] - 1, top + 2 * cell[1] // 3], fill=rgb(fg))
                x += 1
    return image


def braille_thumbnail(strips: Sequence[Any], max_width: int, max_height: int) -> list[str]:
    """
    The text below tier 3: ``strips`` shrunk into at most ``max_width`` by ``max_height`` braille cells, a dot for
    each run of characters that is not blank.
    """
    width = max((strip.cell_length for strip in strips), default=0)
    height = len(strips)
    if not width or not height:
        return []
    dots_w, dots_h = max_width * BRAILLE_DOTS[0], max_height * BRAILLE_DOTS[1]
    scale = max(width / dots_w, height / dots_h, 1.0)
    cols = min(max_width, int(width / scale / BRAILLE_DOTS[0]) + 1)
    rows = min(max_height, int(height / scale / BRAILLE_DOTS[1]) + 1)
    dots = [[0] * cols for _ in range(rows)]
    for y, strip in enumerate(strips):
        x = 0
        for segment in strip:
            for char in segment.text:
                if not char.isspace():
                    dx, dy = int(x / scale), int(y / scale)
                    cx, cy = dx // BRAILLE_DOTS[0], dy // BRAILLE_DOTS[1]
                    if cx < cols and cy < rows:
                        dots[cy][cx] |= _BRAILLE_BITS[dy % 4][dx % 2]
                x += 1
    return ["".join(chr(0x2800 + bits) for bits in row) for row in dots]


__all__ = [
    "PIXELS_PER_CELL",
    "braille_thumbnail",
    "columns_image",
    "minimap_image",
    "new_image",
    "placeholder",
    "rgb",
    "strips_image",
    "style_color",
]
