"""
CharCanvas: boxes, lines that merge at junctions and crossings, arrow heads, text, and strips.
"""

# pylint: disable=missing-class-docstring,no-self-use

from __future__ import annotations

import textwrap
import unittest

from rich.style import Style

from angrmanagement.present.spans import Line
from angrmanagement.tui.canvas import DOWN, CharCanvas


def art(text: str) -> str:
    """Expected canvas text: the dedented lines, each padded to the canvas width by the caller's canvas."""
    return textwrap.dedent(text).strip("\n")


def drawn(canvas: CharCanvas) -> str:
    return "\n".join(canvas.row_text(y).rstrip() for y in range(canvas.height)).rstrip("\n")


class TestCharCanvas(unittest.TestCase):
    def test_box(self):
        canvas = CharCanvas(6, 3)
        canvas.box(0, 0, 4, 3)
        assert drawn(canvas) == art(
            """
            ┌──┐
            │  │
            └──┘
            """
        )

    def test_box_with_title(self):
        canvas = CharCanvas(12, 3)
        canvas.box(0, 0, 12, 3, title="main")
        assert drawn(canvas) == art(
            """
            ┌─ main ───┐
            │          │
            └──────────┘
            """
        )

    def test_polyline_corners_and_arrow(self):
        canvas = CharCanvas(6, 5)
        canvas.polyline([(1, 0), (1, 2), (4, 2), (4, 4)])
        assert drawn(canvas) == "\n".join([" │", " │", " └──┐", "    │", "    ▼"])

    def test_arrows_point_the_way_the_line_goes(self):
        for points, head in [
            ([(0, 2), (0, 0)], "▲"),
            ([(4, 1), (0, 1)], "◀"),
            ([(0, 1), (4, 1)], "▶"),
            ([(2, 0), (2, 2)], "▼"),
        ]:
            canvas = CharCanvas(5, 3)
            canvas.polyline(points)
            x, y = points[-1]
            assert canvas.chars[y][x] == head, points

    def test_junction(self):
        canvas = CharCanvas(6, 5)
        canvas.vline(2, 0, 4)
        canvas.hline(2, 5, 2)
        assert drawn(canvas) == "\n".join(["  │", "  │", "  ├───", "  │", "  │"])

    def test_two_edges_from_one_point(self):
        canvas = CharCanvas(7, 4)
        canvas.polyline([(3, 0), (3, 1), (1, 1), (1, 3)])
        canvas.polyline([(3, 0), (3, 1), (5, 1), (5, 3)])
        assert drawn(canvas) == "\n".join(["   │", " ┌─┴─┐", " │   │", " ▼   ▼"])

    def test_crossing(self):
        canvas = CharCanvas(5, 5)
        canvas.vline(2, 0, 4)
        canvas.hline(0, 4, 2)
        assert canvas.row_text(2) == "──┼──"
        assert canvas.chars[1][2] == "│"

    def test_edge_leaving_a_box(self):
        canvas = CharCanvas(6, 5)
        canvas.box(0, 0, 6, 3)
        canvas.mark(2, 2, DOWN)
        canvas.polyline([(2, 3), (2, 4)])
        assert drawn(canvas) == art(
            """
            ┌────┐
            │    │
            └─┬──┘
              │
              ▼
            """
        )

    def test_text_is_not_covered_by_lines(self):
        canvas = CharCanvas(8, 3)
        canvas.text(1, 1, "push")
        canvas.hline(0, 7, 1)
        assert canvas.row_text(1) == "─push───"

    def test_blit_and_strips(self):
        canvas = CharCanvas(10, 2, style="bg")
        line = Line().append("mov", "mnemonic").append(" ").append("rax", "operand")
        canvas.blit([line, Line().append("ret", "mnemonic")], 1, 0, base_style="block", width=8)
        styles = {"bg": Style(bgcolor="white"), "block": Style(bgcolor="grey50")}

        def style_of(key: str) -> Style:
            out = Style.null()
            for part in key.split():
                out += styles.get(part, Style(bold=part == "mnemonic", italic=part == "operand"))
            return out

        strips = canvas.to_strips((0, 0, 12, 2), style_of)
        assert [s.text for s in strips] == [" mov rax    ", " ret        "]
        first = list(strips[0])
        # the padding inside the block, the canvas edge outside it, and the blank past the canvas
        assert [seg.text for seg in first] == [" ", "mov", " ", "rax", " ", " ", "  "]
        assert first[1].style is not None and first[1].style.bold
        assert first[3].style is not None and first[3].style.italic
        assert all(s.cell_length == 12 for s in strips)
        # a window past the bottom is blank
        assert canvas.to_strips((0, 5, 4, 1), style_of)[0].text == "    "


if __name__ == "__main__":
    unittest.main()
