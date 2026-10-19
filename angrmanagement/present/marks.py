"""
Marks: short annotations next to instructions, for both frontends.

A :class:`Mark` is what a plugin's ``decorate_insn`` or ``block_marks`` hook returns, and what the disassembly
presenter makes of hooks, breakpoints and symbolic execution find/avoid addresses: a little text in a style, placed
before the instruction text, after it, or on a line of its own above it, with an optional action that runs when the
user activates it (Enter on the mark's line in the terminal, a click in Qt).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

MarkPosition = Literal["before", "after", "line"]


@dataclass(frozen=True)
class Mark:
    """
    An annotation on an instruction.

    :param text:        What it says, such as ``"BP"`` or ``"hook"``.
    :param style_key:   Its style key (a configuration entry name or an extra style).
    :param position:    ``"before"`` the instruction text, ``"after"`` it, or its own ``"line"`` above it.
    :param priority:    Marks with a higher priority come first.
    :param action:      Called with no arguments when the user activates the mark; None for none.
    :param addr:        The instruction it belongs to, where the hook that made it does not say (``block_marks``).
    """

    text: str
    style_key: str = ""
    position: MarkPosition = "after"
    priority: int = 0
    action: Callable[[], object] | None = None
    addr: int | None = None


def sorted_marks(marks: Iterable[Mark]) -> list[Mark]:
    """``marks`` in the order to show them: highest priority first, then in the order given."""
    return sorted(marks, key=lambda mark: -mark.priority)


__all__ = ["Mark", "MarkPosition", "sorted_marks"]
