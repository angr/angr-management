"""
The patterns pane of the pseudocode view, as a table model.

The Qt view docks a ``QPatternLibrary`` beside the pseudocode: the project's patterns, with what the outliner pass did
with each in the function shown, a check box that marks a pattern to be turned on or off by the next "Apply Patterns &
Redecompile", and one that highlights its matches in the pseudocode. :class:`PatternLibraryModel` is that table for a
frontend that draws table models; the marks and the apply work as the Qt widget's do.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from .menus import Menu, MenuEntry
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from .code import CodePresenter


class PatternLibraryModel(ListTableModel[Any]):
    """
    The project's patterns and their numbers in the function the pseudocode view shows.

    :param presenter:   The pseudocode view's presenter: its function, its highlights and its decompile.
    :param on_status:   Called with a line to show the user (what changed, or why nothing did).
    """

    COLUMNS: ClassVar[list[Column]] = [
        Column("Pattern", 20),
        Column("Enabled", 9, checkable=True),
        Column("Highlight", 9, checkable=True),
        Column("Matches", 7, align="right"),
        Column("Outlined", 8, align="right"),
        Column("Call", 16),
        Column("Min similarity", 6, align="right"),
        Column("From", 10, stretch=True),
    ]
    ENABLED, HIGHLIGHT = 1, 2

    def __init__(self, presenter: CodePresenter, on_status: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self.presenter = presenter
        self.on_status = on_status
        #: pattern name -> the enabled state a click asked for, where it differs from the project's
        self.pending: dict[str, bool] = {}
        self.reload()

    @property
    def kb(self) -> Any:
        return self.presenter.instance.kb

    def _func_addr(self) -> int | None:
        function: Any = self.presenter.function
        return None if function.am_none else function.am_obj.addr

    def _status(self, message: str) -> None:
        if self.on_status is not None:
            self.on_status(message)

    def reload(self) -> None:
        """Read the patterns again; a mark goes away once the project agrees with it, or its pattern is gone."""
        kb = self.kb
        patterns = [] if kb is None else sorted(kb.patterns, key=lambda p: p.name)
        by_name = {stored.name: stored for stored in patterns}
        self.pending = {
            name: on for name, on in self.pending.items() if name in by_name and by_name[name].enabled != on
        }
        self.set_rows(patterns)

    def _stats(self, stored: Any) -> Any:
        func_addr = self._func_addr()
        return self.kb.patterns.stats(func_addr, stored.name) if func_addr is not None else None

    def column_text(self, obj: Any, col: int) -> str:
        name = self.COLUMNS[col].name
        if name == "Pattern":
            return obj.name
        if name == "Enabled":
            enabled = self.pending.get(obj.name, obj.enabled)
            return ("on" if enabled else "off") + (" (unapplied)" if obj.name in self.pending else "")
        if name == "Highlight":
            return ""
        if name in ("Matches", "Outlined"):
            # the pass records every pattern it searched, so no numbers means the pattern was not enabled then
            stats = self._stats(obj)
            return str(0 if stats is None else (stats.matches if name == "Matches" else stats.outlined))
        if name == "Call":
            return obj.pattern.call_name
        if name == "Min similarity":
            return f"{obj.min_similarity:.0%}"
        return f"{obj.origin_func:#x}" if obj.origin_func is not None else ""

    def style_key(self, obj: Any, col: int) -> str | None:
        return "bold" if obj.name in self.pending else None

    def tooltip(self, obj: Any, col: int) -> str | None:
        if col != self.HIGHLIGHT:
            return None
        calls = self.presenter.pattern_call_count(obj.name)
        if calls:
            return f"Highlight the {calls} call(s) to {obj.pattern.call_name}"
        return "No call to this pattern in this function to highlight"

    def is_checked(self, obj: Any, col: int) -> bool:
        if col == self.ENABLED:
            return bool(self.pending.get(obj.name, obj.enabled))
        if col == self.HIGHLIGHT:
            return self.presenter.is_pattern_highlighted(obj.name)
        return False

    def set_checked(self, row: int, col: int, checked: bool) -> bool:
        stored = self.row(row)
        if stored is None:
            return False
        if col == self.ENABLED:
            self.mark(stored, checked)
            return True
        if col == self.HIGHLIGHT:
            self.presenter.set_pattern_highlight(stored.name, checked)
            self.rows_changed(row, row)
            return True
        return False

    def key_of(self, obj: Any) -> Any:
        return obj.name

    def on_activate(self, obj: Any) -> None:
        self.edit(obj)

    #
    # Operations
    #

    def mark(self, stored: Any, enabled: bool) -> None:
        """Mark ``stored`` to be turned on or off by the next apply; marking it back clears the mark."""
        if enabled == stored.enabled:
            self.pending.pop(stored.name, None)
        else:
            self.pending[stored.name] = enabled
        self.reload()
        if self.pending:
            self._status(f"{len(self.pending)} pattern change(s) not applied yet")

    def apply_pending(self) -> bool:
        """
        Write the marked changes and decompile the function again. Returns False, and does not decompile, when the
        marks leave the set of enabled patterns as it was.
        """
        patterns = self.kb.patterns
        changes = {name: on for name, on in self.pending.items() if (s := patterns.get(name)) and s.enabled != on}
        self.pending.clear()
        if not changes:
            self.reload()
            self._status("the enabled patterns did not change; nothing to apply")
            return False
        for name, on in changes.items():
            patterns.set_enabled(name, on)
        self.presenter.workspace.on_patterns_changed()
        self._status(", ".join(f"{name} is {'on' if on else 'off'}" for name, on in sorted(changes.items())))
        if not self.presenter.function.am_none:
            self.presenter.view_or_self("decompile")(reset_cache=True)
        return True

    def edit(self, stored: Any) -> None:
        """Open ``stored`` in the pattern view."""
        if self.presenter.workspace.edit_pattern(stored) is None:
            self._status("the pattern view is not in this frontend yet")

    def _matches_here(self, patterns: Sequence[Any], calls_count: bool = False) -> dict[str, list[frozenset[int]]]:
        """Each pattern's matches in the function shown at its last decompilation; with ``calls_count``, a pattern
        whose calls the pseudocode shows counts even without them."""
        function: Any = self.presenter.function
        if function.am_none:
            self._status("no function is decompiled in the pseudocode view")
            return {}
        func_addr = function.am_obj.addr
        found = {}
        for stored in patterns:
            stats = self.kb.patterns.stats(func_addr, stored.name)
            if stats is not None and stats.matches:
                found[stored.name] = list(stats.match_addrs)
            elif calls_count and self.presenter.pattern_call_count(stored.name):
                found[stored.name] = []
        missing = [s.name for s in patterns if s.name not in found]
        if missing:
            self._status(f"no matches in {function.am_obj.name} at its last decompilation: {', '.join(missing)}")
        return found

    def highlight_in_pseudocode(self, patterns: Sequence[Any]) -> None:
        """Band the patterns' matches in the pseudocode view's function."""
        for name in self._matches_here(patterns, calls_count=True):
            self.presenter.set_pattern_highlight(name, True)
        self.reload()

    def highlight_in_disassembly(self, patterns: Sequence[Any]) -> None:
        """Paint every instruction the patterns' matches cover in the pseudocode view's function."""
        found = self._matches_here(patterns)
        addrs = {a for copies in found.values() for copy in copies for a in copy}
        if addrs:
            self.presenter.workspace.highlight_in_disassembly(addrs)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:
        selected = self.objects(rows)
        return Menu(
            "Patterns",
            [
                MenuEntry(
                    "Highlight patterns in pseudocode",
                    lambda: self.highlight_in_pseudocode(selected),
                    enabled=bool(selected),
                ),
                MenuEntry(
                    "Highlight patterns in disassembly",
                    lambda: self.highlight_in_disassembly(selected),
                    enabled=bool(selected),
                ),
                MenuEntry("Edit pattern...", lambda: self.edit(selected[0]), enabled=len(selected) == 1),
                MenuEntry("Apply Patterns && Redecompile", self.apply_pending, enabled=bool(self.pending)),
                MenuEntry("Clear highlights", self.presenter.clear_pattern_highlight),
            ],
        )


__all__ = ["PatternLibraryModel"]
