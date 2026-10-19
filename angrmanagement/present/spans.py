"""
Styled text without a toolkit: the span IR.

A :class:`Span` is a run of text with a *style key* and the object that owns the text. A :class:`Line` is a row of
spans and a :class:`Doc` is a list of lines. Style keys are configuration entry names, such as
``"disasm_view_node_mnemonic_color"``, or the names in :data:`angrmanagement.present.theme.EXTRA_STYLES`; several keys
separated by spaces combine (see :meth:`angrmanagement.present.theme.Theme.style`). The owner (``node``) is what a
click on the text selects: a block tree node, an instruction node, an operand node, or None for decoration.

Frontends draw a document however they like: the Qt frontend puts one text item per span on its scene, the terminal
frontend writes cells. Hit testing goes from a line and a column back to the span, and from the span to its node.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


def utf16_length(text: str) -> int:
    """The length of ``text`` in UTF-16 code units, which is how Qt's text documents count positions."""
    return len(text.encode("utf-16-le")) // 2


@dataclass(frozen=True)
class Span:
    """
    A run of text in one style.

    :param text:    The text; it never holds a newline (a :class:`Line` is one row).
    :param style:   The style key, or several separated by spaces; empty for the frontend's default.
    :param node:    The object the text belongs to, for hit testing and selection; None for decoration.
    """

    text: str
    style: str = ""
    node: Any = None

    @property
    def width(self) -> int:
        """How many terminal cells the text takes, one per character."""
        return len(self.text)

    def with_style(self, style: str) -> Span:
        """This span with ``style`` added to its style keys."""
        if not style:
            return self
        return Span(self.text, f"{self.style} {style}".strip(), self.node)


@dataclass
class Line:
    """A row of spans."""

    spans: list[Span] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "".join(span.text for span in self.spans)

    @property
    def width(self) -> int:
        return sum(span.width for span in self.spans)

    def append(self, text: str, style: str = "", node: Any = None) -> Line:
        """Add a span (nothing for empty text); returns the line, so calls chain."""
        if text:
            self.spans.append(Span(text, style, node))
        return self

    def extend(self, spans: Iterable[Span]) -> Line:
        self.spans.extend(span for span in spans if span.text)
        return self

    def pad(self, width: int, style: str = "") -> Line:
        """Add spaces until the line is ``width`` cells wide."""
        missing = width - self.width
        if missing > 0:
            self.spans.append(Span(" " * missing, style))
        return self

    def span_at(self, column: int) -> tuple[Span, int] | None:
        """The span under ``column`` (in cells, from 0) and the column's offset into it, or None past the end."""
        if column < 0:
            return None
        start = 0
        for span in self.spans:
            if start <= column < start + span.width:
                return span, column - start
            start += span.width
        return None

    def node_at(self, column: int) -> Any:
        """The node of the span under ``column``, or None."""
        hit = self.span_at(column)
        return hit[0].node if hit is not None else None

    def columns_of(self, node: Any) -> list[tuple[int, int]]:
        """The ``(start, end)`` columns of every span whose node is ``node``."""
        out = []
        start = 0
        for span in self.spans:
            if span.node is node and node is not None:
                out.append((start, start + span.width))
            start += span.width
        return out

    def restyled(self, style: str) -> Line:
        """A copy of the line with ``style`` added to every span."""
        return Line([span.with_style(style) for span in self.spans])


@dataclass
class Doc:
    """Lines of spans."""

    lines: list[Line] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(line.text for line in self.lines)

    @property
    def width(self) -> int:
        return max((line.width for line in self.lines), default=0)

    @property
    def height(self) -> int:
        return len(self.lines)

    def __iter__(self) -> Iterator[Line]:
        return iter(self.lines)

    def __len__(self) -> int:
        return len(self.lines)

    def append(self, line: Line) -> Doc:
        self.lines.append(line)
        return self

    def extend(self, lines: Iterable[Line]) -> Doc:
        self.lines.extend(lines)
        return self

    def node_at(self, row: int, column: int) -> Any:
        """The node under ``(row, column)``, or None."""
        if 0 <= row < len(self.lines):
            return self.lines[row].node_at(column)
        return None


def split_lines(spans: Iterable[Span]) -> list[Line]:
    """
    Break a flat run of spans into lines at the newlines in their text, as a text document lays it out.

    ``"a\\nb"`` gives two lines and ``"a\\n"`` gives two as well, the second one empty: a QTextDocument makes a new
    block for every newline, so text that ends with one is a row taller, and the terminal shows the same rows.
    """
    lines = [Line()]
    for span in spans:
        parts = span.text.split("\n")
        for idx, part in enumerate(parts):
            if idx > 0:
                lines.append(Line())
            if part:
                lines[-1].spans.append(Span(part, span.style, span.node))
    return lines


__all__ = ["Doc", "Line", "Span", "split_lines", "utf16_length"]
