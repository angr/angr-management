"""
Tables without a toolkit.

A :class:`TableModel` describes a table: its :class:`Column` list, its rows, and for each cell a :class:`Cell` with the
text, a style key (see angrmanagement.present.theme) and a sort key. It sorts and filters itself, says what happens
when a row is activated, and builds the context menu of a set of rows. ``about_to_change`` and ``changed`` tell a
frontend when to redraw. The Qt frontend wraps a model in ``QtTableModelAdapter`` (angrmanagement.ui.widgets.qt_table),
the terminal one in ``TableWidget`` (angrmanagement.tui.widgets.table).

:class:`ListTableModel` implements the protocol over a list of row objects; a concrete table subclasses it and says
how one row object appears in each column.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Protocol

from angrmanagement.logic.signal import Signal

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable, Iterable, Sequence

    from .menus import Menu
    from .theme import StyleSpec

#: ``changed`` and ``about_to_change`` kinds: everything changed; the rows were reordered or filtered; rows
#: ``first`` to ``last`` were appended; the cells of rows ``first`` to ``last`` changed.
RESET = "reset"
LAYOUT = "layout"
APPENDED = "appended"
DATA = "data"


@dataclass(frozen=True)
class Column:
    """
    A table column.

    :param name:        The header text.
    :param width_hint:  A good width in characters; 0 to fit the contents.
    :param align:       ``"left"``, ``"right"`` or ``"center"``.
    :param stretch:     Whether the column takes the width left over.
    :param checkable:   Whether the cells are check boxes (see :attr:`Cell.checked`).
    :param editable:    Whether the cells can be edited in place.
    """

    name: str
    width_hint: int = 0
    align: str = "left"
    stretch: bool = False
    checkable: bool = False
    editable: bool = False


@dataclass(frozen=True)
class Cell:
    """
    One cell.

    :param text:        What to show.
    :param style_key:   How to colour it (angrmanagement.present.theme), or None for the default.
    :param sort_key:    What the column sorts by; ``text`` when None.
    :param tooltip:     More text to show on demand.
    :param checked:     For a check box cell, whether it is checked.
    :param style:       Colours that do not come from the theme, such as a plugin's; laid over ``style_key``.
    """

    text: str
    style_key: str | None = None
    sort_key: Any = None
    tooltip: str | None = None
    checked: bool | None = None
    style: StyleSpec | None = None


class TableModel(Protocol):
    """What a table frontend needs from a model."""

    about_to_change: Signal
    changed: Signal

    @property
    def columns(self) -> list[Column]: ...

    @property
    def row_count(self) -> int: ...

    def cell(self, row: int, col: int) -> Cell: ...

    def row_key(self, row: int) -> Hashable: ...

    def sort(self, col: int, descending: bool = False) -> None: ...

    def filter(self, text: str) -> None: ...

    def activate(self, row: int) -> None: ...

    def context_menu(self, rows: Sequence[int]) -> Menu | None: ...

    def set_checked(self, row: int, col: int, checked: bool) -> bool: ...

    def set_text(self, row: int, col: int, text: str) -> bool: ...


def wildcard_to_regex(pattern: str) -> str:
    """
    Turn a shell-style wildcard into a regular expression that matches it anywhere in a string, as Qt's
    ``QRegularExpression.wildcardToRegularExpression(pattern, UnanchoredWildcardConversion)`` does on Unix: ``*`` and
    ``?`` do not match ``/``, ``[...]`` is a character class and ``[!...]`` its complement.
    """
    out = []
    i = 0
    n = len(pattern)
    while i < n:
        c = pattern[i]
        i += 1
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c in "\\$()+.^{|}":
            out.append("\\" + c)
        elif c == "[":
            out.append(c)
            if i < n:
                if pattern[i] == "!":
                    out.append("^")
                    i += 1
                if i < n and pattern[i] == "]":
                    out.append(pattern[i])
                    i += 1
                while i < n and pattern[i] != "]":
                    if pattern[i] == "/":
                        # a "/" in a character class makes the whole expression invalid in Qt
                        return "".join(out)
                    if pattern[i] == "\\":
                        out.append("\\")
                    out.append(pattern[i])
                    i += 1
        else:
            out.append(c)
    return "".join(out)


def compile_filter(pattern: str | re.Pattern | None, regex: bool = False) -> Callable[[str], bool]:
    """
    A predicate for a filter box: a compiled pattern or ``regex=True`` filters by regular expression, anything else by
    wildcard; both ignore case. An empty pattern matches everything, and an invalid one matches nothing.
    """
    if isinstance(pattern, re.Pattern):
        source = str(pattern.pattern)
    elif not pattern:
        return lambda _text: True
    else:
        source = pattern if regex else wildcard_to_regex(pattern)
    try:
        compiled = re.compile(source, re.IGNORECASE)
    except re.error:
        return lambda _text: False
    return lambda text: compiled.search(text) is not None


class ListTableModel[T]:
    """
    A table over a list of row objects.

    A subclass sets :attr:`COLUMNS` and overrides :meth:`column_text`, and as needed :meth:`column_value` (the sort
    key), :meth:`style_key`, :meth:`tooltip`, :meth:`matches`, :meth:`on_activate` and :meth:`context_menu`. Change the
    rows with :meth:`set_rows` or :meth:`append_rows`, on the UI thread.
    """

    COLUMNS: ClassVar[list[Column]] = []

    def __init__(self) -> None:
        name = type(self).__name__
        self.about_to_change = Signal(str, int, int, name=f"{name}.about_to_change")
        self.changed = Signal(str, int, int, name=f"{name}.changed")
        self._all: list[T] = []
        self._rows: list[T] = []
        self._filter_text: str = ""
        self._sort_column: int | None = None
        self._sort_descending: bool = False

    #
    # The protocol
    #

    @property
    def columns(self) -> list[Column]:
        return list(self.COLUMNS)

    @property
    def row_count(self) -> int:
        return len(self._rows)

    @property
    def total_count(self) -> int:
        """The number of rows before filtering."""
        return len(self._all)

    def cell(self, row: int, col: int) -> Cell:
        obj = self._rows[row]
        text = self.column_text(obj, col)
        return Cell(
            text,
            style_key=self.style_key(obj, col),
            sort_key=self.column_value(obj, col),
            tooltip=self.tooltip(obj, col),
            checked=self.is_checked(obj, col) if self._column(col).checkable else None,
            style=self.explicit_style(obj, col),
        )

    def row_key(self, row: int) -> Hashable:
        return self.key_of(self._rows[row])

    def sort(self, col: int, descending: bool = False) -> None:
        def do_sort() -> None:
            self._sort_column = col
            self._sort_descending = descending
            self._all = self._sorted(self._all)
            self._rows = self._sorted(self._rows)

        self._notify(LAYOUT, do_sort)

    def filter(self, text: str) -> None:
        def do_filter() -> None:
            previous = self._filter_text
            self._filter_text = text
            if previous and previous in text and self._can_refine():
                # incremental: a longer keyword can only drop rows
                self._rows = [obj for obj in self._rows if self._accepts(obj)]
            else:
                self._rows = [obj for obj in self._all if self._accepts(obj)]

        self._notify(LAYOUT, do_filter)

    def activate(self, row: int) -> None:
        obj = self.row(row)
        if obj is not None:
            self.on_activate(obj)

    def context_menu(self, rows: Sequence[int]) -> Menu | None:  # pylint:disable=unused-argument,no-self-use
        return None

    #
    # Rows
    #

    @property
    def filter_text(self) -> str:
        return self._filter_text

    @property
    def sort_order(self) -> tuple[int | None, bool]:
        """The column the rows are sorted by (None for their own order) and whether in descending order."""
        return self._sort_column, self._sort_descending

    @property
    def rows(self) -> list[T]:
        """The rows shown, after filtering and sorting."""
        return self._rows

    @property
    def all_rows(self) -> list[T]:
        """Every row, before filtering."""
        return self._all

    def row(self, row: int) -> T | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def objects(self, rows: Iterable[int]) -> list[T]:
        """The row objects at ``rows``, in order, skipping rows that do not exist."""
        return [obj for obj in (self.row(r) for r in sorted(set(rows))) if obj is not None]

    def index_of(self, obj: T) -> int | None:
        """The row that shows ``obj``, or None if it is filtered out or absent."""
        try:
            return self._rows.index(obj)
        except ValueError:
            return None

    def set_rows(self, objs: Iterable[T]) -> None:
        """Replace every row."""

        def do_set() -> None:
            self._all = self._sorted(list(objs))
            self._rows = [obj for obj in self._all if self._accepts(obj)]

        self._notify(RESET, do_set)

    def append_rows(self, objs: Iterable[T]) -> None:
        """Add rows at the end; with a sort order set, the rows are sorted again instead."""
        objs = list(objs)
        if not objs:
            return
        if self._sort_column is not None:
            self.set_rows(self._all + objs)
            return
        shown = [obj for obj in objs if self._accepts(obj)]
        first = len(self._rows)

        def do_append() -> None:
            self._all.extend(objs)
            self._rows.extend(shown)

        if not shown:
            do_append()
            return
        self._notify(APPENDED, do_append, first, first + len(shown) - 1)

    def remove_first_rows(self, count: int) -> None:
        """Drop the first ``count`` rows (before filtering), such as the oldest entries of a capped history."""
        if count <= 0:
            return
        self.set_rows(self._all[count:])

    def rows_changed(self, first: int = 0, last: int = -1) -> None:
        """Say that the cells of rows ``first`` to ``last`` (the last row when -1) changed."""
        if last < 0:
            last = len(self._rows) - 1
        if last < first:
            return
        self._notify(DATA, lambda: None, first, last)

    def refilter(self) -> None:
        """Apply the filter again, after the row objects changed in a way that may affect it."""
        self.filter(self._filter_text)

    #
    # What a table says about one row object
    #

    def column_text(self, obj: T, col: int) -> str:
        raise NotImplementedError

    def column_value(self, obj: T, col: int) -> Any:
        """What column ``col`` sorts by; its text by default."""
        return self.column_text(obj, col)

    def style_key(self, obj: T, col: int) -> str | None:  # pylint:disable=unused-argument,no-self-use
        return None

    def explicit_style(self, obj: T, col: int) -> StyleSpec | None:  # pylint:disable=unused-argument,no-self-use
        return None

    def tooltip(self, obj: T, col: int) -> str | None:  # pylint:disable=unused-argument,no-self-use
        return None

    def is_checked(self, obj: T, col: int) -> bool:  # pylint:disable=unused-argument,no-self-use
        return False

    def set_checked(self, row: int, col: int, checked: bool) -> bool:  # pylint:disable=unused-argument,no-self-use
        """Check or uncheck a check box cell; whether the model took it."""
        return False

    def set_text(self, row: int, col: int, text: str) -> bool:  # pylint:disable=unused-argument,no-self-use
        """Edit a cell; whether the model took it."""
        return False

    def matches(self, obj: T, keyword: str) -> bool:
        """Whether ``obj`` passes the filter ``keyword`` (already lower case); any column containing it by default."""
        return any(keyword in self.column_text(obj, col).lower() for col in range(len(self.columns)))

    def key_of(self, obj: T) -> Hashable:  # pylint:disable=no-self-use
        """A key that identifies ``obj`` among the rows."""
        return id(obj)

    def on_activate(self, obj: T) -> None:
        """The row showing ``obj`` was activated (double-clicked, or Enter)."""

    #
    # Helpers
    #

    def _column(self, col: int) -> Column:
        columns = self.columns
        if 0 <= col < len(columns):
            return columns[col]
        return Column("")

    def _can_refine(self) -> bool:  # pylint:disable=no-self-use
        """Whether a longer filter keyword can be applied to the rows already shown."""
        return True

    def _accepts(self, obj: T) -> bool:
        if not self._filter_text:
            return True
        return self.matches(obj, self._filter_text.lower())

    def _sorted(self, objs: list[T]) -> list[T]:
        col = self._sort_column
        if col is None:
            return objs
        return sorted(objs, key=lambda obj: _sortable(self.column_value(obj, col)), reverse=self._sort_descending)

    def _notify(self, kind: str, change: Callable[[], None], first: int = 0, last: int = -1) -> None:
        self.about_to_change.emit(kind, first, last)
        change()
        self.changed.emit(kind, first, last)


class _Sortable:
    """A sort key that orders values of different types (numbers, strings, None) without raising."""

    __slots__ = ("rank", "value")

    rank: int
    value: Any

    def __init__(self, value: Any) -> None:
        if value is None:
            self.rank, self.value = 2, 0
        elif isinstance(value, bool | int | float):
            self.rank, self.value = 0, value
        elif isinstance(value, list | tuple):
            self.rank, self.value = 1, tuple(value)
        else:
            self.rank, self.value = 1, value if isinstance(value, str) else str(value)

    def __lt__(self, other: _Sortable) -> bool:
        if self.rank != other.rank:
            return self.rank < other.rank
        try:
            return self.value < other.value
        except TypeError:
            return str(self.value) < str(other.value)


def _sortable(value: Any) -> _Sortable:
    return _Sortable(value)
