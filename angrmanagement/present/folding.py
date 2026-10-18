"""
Code folding without a toolkit, as the Qt pseudocode editor folds: pyqodeng's ``CharBasedFoldDetector`` (a line that
ends with ``{``, or a ``{`` on a line of its own, opens a level; a line after one holding ``}`` closes it) and its
``FoldScope`` (a trigger line folds the lines after it whose level is deeper, less the blank lines at the end).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

OPEN_CHAR = "{"
CLOSE_CHAR = "}"


def fold_levels(texts: Sequence[str]) -> tuple[list[int], set[int]]:
    """
    The fold level of each line of ``texts`` and the lines that are fold triggers, as pyqodeng's
    ``FoldDetector.process_block`` with a ``CharBasedFoldDetector`` computes them line by line.
    """
    levels = [0] * len(texts)
    triggers: set[int] = set()
    blank = [not text.strip() for text in texts]
    for row, text in enumerate(texts):
        # the previous non-blank line; the first line counts whether blank or not, as in the Qt highlighter
        prev = row - 1 if row else None
        while prev is not None and prev > 0 and blank[prev]:
            prev -= 1
        prev_level = levels[prev] if prev is not None else 0
        if blank[row]:
            level = prev_level
        else:
            prev_text = texts[prev].strip() if prev is not None else ""
            stripped = text.strip()
            if stripped == OPEN_CHAR or (prev_text.endswith(OPEN_CHAR) and prev_text != OPEN_CHAR):
                level = prev_level + 1
            elif CLOSE_CHAR in prev_text:
                level = prev_level - 1
            else:
                level = prev_level
        if level > prev_level:
            # the blank lines before take the new level, and the line before them is the trigger
            before = row - 1
            while before >= 0 and blank[before]:
                levels[before] = level
                before -= 1
            if before >= 0:
                triggers.add(before)
        if not blank[row] and prev is not None:
            if level > prev_level:
                triggers.add(prev)
            else:
                triggers.discard(prev)
        levels[row] = level
        if row and blank[row - 1]:
            triggers.discard(row - 1)
    return levels, triggers


class FoldMap:
    """The fold triggers of a text, the lines each folds, and which are folded."""

    def __init__(self, texts: Sequence[str]) -> None:
        self.texts = list(texts)
        self.levels, triggers = fold_levels(self.texts)
        #: trigger line -> the last line it folds; the trigger itself stays shown
        self.scopes: dict[int, int] = {}
        for row in sorted(triggers):
            last = self._scope_end(row)
            if last > row:
                self.scopes[row] = last
        #: the folded triggers
        self.folded: set[int] = set()
        self._visible: list[int] | None = None

    def _scope_end(self, trigger: int) -> int:
        """The last line ``trigger`` folds, as ``FoldScope.get_range(ignore_blank_lines=True)``."""
        count = len(self.texts)
        if trigger + 1 >= count:
            return trigger
        ref = self.levels[trigger]
        if ref == self.levels[trigger + 1]:
            ref -= 1
        last = trigger + 1
        row = trigger + 1
        while row < count and self.levels[row] > ref:
            last = row
            row += 1
        while last and not self.texts[last].strip():
            last -= 1
        return last

    #
    # What is shown
    #

    def is_trigger(self, row: int) -> bool:
        return row in self.scopes

    def visible_rows(self) -> list[int]:
        """The lines shown, in order: every line no folded trigger hides."""
        if self._visible is None:
            hidden: set[int] = set()
            for trigger in self.folded:
                hidden.update(range(trigger + 1, self.scopes[trigger] + 1))
            self._visible = [row for row in range(len(self.texts)) if row not in hidden]
        return self._visible

    def is_hidden(self, row: int) -> bool:
        return any(trigger < row <= self.scopes[trigger] for trigger in self.folded)

    def _changed(self) -> None:
        self._visible = None

    #
    # Folding and unfolding
    #

    def scope_of(self, row: int) -> int | None:
        """
        The trigger of the scope ``row`` is in: ``row`` itself when it is a trigger, else the nearest trigger above
        it a level up, as ``FoldScope.find_parent_scope``; None outside every scope.
        """
        if row in self.scopes:
            return row
        if not 0 <= row < len(self.texts):
            return None
        probe = row
        while probe < len(self.texts) - 1 and not self.texts[probe].strip():
            probe += 1
        ref = self.levels[probe] - 1
        while row and (row not in self.scopes or self.levels[row] > ref):
            row -= 1
        return row if row in self.scopes else None

    def fold(self, trigger: int) -> None:
        if trigger in self.scopes:
            self.folded.add(trigger)
            self._changed()

    def unfold(self, trigger: int) -> None:
        """Show what ``trigger`` folds, with the triggers inside it unfolded, as ``FoldScope.unfold``."""
        if trigger not in self.scopes:
            return
        last = self.scopes[trigger]
        self.folded = {other for other in self.folded if not trigger <= other <= last}
        self._changed()

    def toggle(self, trigger: int) -> bool:
        """Fold ``trigger`` or unfold it; whether it is a trigger."""
        if trigger not in self.scopes:
            return False
        if trigger in self.folded:
            self.unfold(trigger)
        else:
            self.fold(trigger)
        return True

    def reveal(self, row: int) -> bool:
        """Unfold whatever hides ``row``; whether anything did."""
        hiding = [trigger for trigger in self.folded if trigger < row <= self.scopes[trigger]]
        for trigger in hiding:
            self.unfold(trigger)
        return bool(hiding)

    def fold_all(self) -> None:
        """Fold every trigger, as the Qt editor's Collapse all."""
        self.folded = set(self.scopes)
        self._changed()

    def unfold_all(self) -> None:
        self.folded = set()
        self._changed()


__all__ = ["FoldMap", "fold_levels"]
