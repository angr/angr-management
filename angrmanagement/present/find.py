"""
The find bar as a model: the query, the options and the match counter, for frontends that draw their own bar.

It answers what :class:`~angrmanagement.present.disasm.DisasmPresenter` asks of a find bar (the questions it asks the
Qt ``QFindBar``): ``query``, ``mode``, ``compile_query``, ``set_error``, ``set_match_status``,
``set_text_options_visible``, ``activate`` and whether it is open.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from angrmanagement.data.search import loose_whitespace_regex
from angrmanagement.logic.signal import Signal

if TYPE_CHECKING:
    from collections.abc import Sequence


class FindBarState:
    """
    What a find bar shows and holds.

    :param modes:   The modes the bar offers (the first is the default), or None for text only.
    """

    def __init__(self, modes: Sequence[str] | None = None) -> None:
        self.modes = list(modes) if modes else []
        self.mode: str | None = self.modes[0] if self.modes else None
        self.query = ""
        self.case_sensitive = False
        self.use_regex = False
        self.is_open = False
        self.error = False
        self.text_options_visible = True
        self.status = ""
        #: the query, the mode or an option changed
        self.query_changed = Signal()
        #: the bar was closed
        self.closed = Signal()
        #: something the bar shows changed
        self.changed = Signal()

    def set_query(self, text: str) -> None:
        self.query = text
        self.query_changed.emit()
        self.changed.emit()

    def set_mode(self, mode: str) -> None:
        if mode in self.modes:
            self.mode = mode
            self.query_changed.emit()
            self.changed.emit()

    def next_mode(self) -> None:
        if self.modes:
            idx = self.modes.index(self.mode) if self.mode in self.modes else -1
            self.set_mode(self.modes[(idx + 1) % len(self.modes)])

    def set_case_sensitive(self, on: bool) -> None:
        self.case_sensitive = on
        self.query_changed.emit()

    def set_use_regex(self, on: bool) -> None:
        self.use_regex = on
        self.query_changed.emit()

    def compile_query(self, loose_whitespace: bool = False) -> re.Pattern | None:
        """The query as a regex, or None if it is empty or malformed (then flagged as an error)."""
        text = self.query
        if not text:
            self.set_error(False)
            return None
        flags = 0 if self.case_sensitive else re.IGNORECASE
        if self.use_regex:
            source = text
        elif loose_whitespace:
            source = loose_whitespace_regex(text)
        else:
            source = re.escape(text)
        try:
            pattern = re.compile(source, flags)
        except re.error:
            self.set_error(True)
            return None
        self.set_error(False)
        return pattern

    def activate(self, initial_text: str | None = None) -> None:
        if initial_text:
            self.query = initial_text
        self.is_open = True
        self.changed.emit()

    def set_match_status(self, current: int, total: int, capped: bool = False) -> None:
        if not self.query:
            self.status = ""
        elif total == 0:
            self.status = "No matches"
        else:
            self.status = f"{current + 1} of {total}{'+' if capped else ''}"
        self.changed.emit()

    def set_text_options_visible(self, visible: bool) -> None:
        self.text_options_visible = visible

    def set_error(self, is_error: bool) -> None:
        self.error = is_error

    def close_bar(self) -> None:
        self.is_open = False
        self.status = ""
        self.closed.emit()
        self.changed.emit()


__all__ = ["FindBarState"]
