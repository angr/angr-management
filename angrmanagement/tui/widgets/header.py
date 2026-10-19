"""
The header line of a terminal view: a row of words on the left and another on the right, as the Qt view's tool bar
has them. A word with an action is a button; the subclass says which words there are.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.widget import Widget

if TYPE_CHECKING:
    from collections.abc import Callable

    from textual import events

#: A header word and what a click on it does (None: it is a label).
HeaderItem = tuple[str, "Callable[[], Any] | None"]
#: How much of a function's name the header shows.
NAME_WIDTH = 55


def function_label(func: Any) -> str:
    """The name of ``func`` (a Function or None), cut at :data:`NAME_WIDTH` characters, and its address."""
    if func is None:
        return ""
    name = func.demangled_name
    if len(name) > NAME_WIDTH:
        name = name[:NAME_WIDTH] + "..."
    return f"{name} ({func.addr:x})"


class HeaderBar(Widget):
    """One line: the words of :meth:`items`, the left group from the left edge and the right group at the right."""

    DEFAULT_CSS = """
    HeaderBar {
        height: 1;
        width: 1fr;
        background: $panel;
    }
    """

    def __init__(self, view: Any) -> None:
        super().__init__()
        self.view = view
        self._buttons: list[tuple[int, int, Callable[[], Any]]] = []

    def items(self) -> tuple[list[HeaderItem], list[HeaderItem]]:
        """The left and right groups: (text, what a click does, or None for a label)."""
        raise NotImplementedError

    def render(self) -> Text:
        left, right = self.items()
        width = self.size.width
        text = Text(no_wrap=True)
        self._buttons = []

        def add(items: list[HeaderItem]) -> None:
            for idx, (label, action) in enumerate(items):
                if idx:
                    text.append("  " if label != "▾" else " ")
                start = len(text)
                text.append(label, style="bold" if action is not None else "")
                if action is not None:
                    self._buttons.append((start, len(text), action))

        add(left)
        right_width = sum(len(label) for label, _ in right) + 2 * (len(right) - 1)
        text.append(" " * max(2, width - len(text) - right_width))
        add(right)
        return text

    def on_click(self, event: events.Click) -> None:
        for start, end, action in self._buttons:
            if start <= event.x < end:
                event.stop()
                action()
                return


__all__ = ["NAME_WIDTH", "HeaderBar", "HeaderItem", "function_label"]
