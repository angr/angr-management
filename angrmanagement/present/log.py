"""The log view without a toolkit: the log records of an instance, and copying them."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, ClassVar

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async

from .base import InstancePresenter, container
from .keymap import log_keymap
from .menus import Menu, MenuEntry, MenuSeparator
from .tables import Column, ListTableModel

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.log import LogRecord

    from .keymap import Keymap

BENCHMARK_LEVEL = 1

_LEVEL_NAMES = {
    BENCHMARK_LEVEL: "BENCHMARK",
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARNING",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}

# what a frontend without icons shows in the first column, and its style key
_LEVEL_MARKS = {
    BENCHMARK_LEVEL: ("⏱", "log.benchmark"),
    logging.WARNING: ("⚠", "log.warning"),
    logging.ERROR: ("✖", "log.error"),
    logging.CRITICAL: ("✖", "log.error"),
}


def level_to_text(loglevel: int) -> str:
    return _LEVEL_NAMES.get(loglevel, "")


def record_line(record: LogRecord) -> str:
    """One record as the "copy" actions write it: level, timestamp, source and content."""
    return f"{level_to_text(record.level)} | {record.timestamp!s} | {record.source} | {record.content}"


class LogTableModel(ListTableModel["LogRecord"]):
    """The log records of an instance, oldest first."""

    COL_ICON = 0
    COL_TIMESTAMP = 1
    COL_SOURCE = 2
    COL_CONTENT = 3

    COLUMNS: ClassVar[list[Column]] = [
        Column("", 2),
        Column("Timestamp", 26),
        Column("Source", 20),
        Column("Content", stretch=True),
    ]
    Headers: ClassVar[list[str]] = [c.name for c in COLUMNS]

    @property
    def log(self) -> list[LogRecord]:
        return self.rows

    def column_text(self, obj: LogRecord, col: int) -> str:
        if col == self.COL_ICON:
            return _LEVEL_MARKS.get(obj.level, ("", None))[0]
        if col == self.COL_TIMESTAMP:
            return str(obj.timestamp)
        if col == self.COL_SOURCE:
            return str(obj.source)
        if col == self.COL_CONTENT:
            return str(obj.content)
        return ""

    def style_key(self, obj: LogRecord, col: int) -> str | None:
        if col == self.COL_ICON:
            return _LEVEL_MARKS.get(obj.level, ("", None))[1]
        return None

    def tooltip(self, obj: LogRecord, col: int) -> str | None:
        return str(obj.content) if col == self.COL_CONTENT else None

    def add_record(self, record: LogRecord) -> None:
        self.append_rows([record])


class LogPresenter(InstancePresenter):
    """The log view: it follows the instance's log, on the UI thread, and copies records."""

    def __init__(self, workspace, instance: Instance, default_docking_position: str = "bottom") -> None:
        super().__init__(workspace, "log", instance, default_docking_position)
        self.base_caption = "Log"
        self.model = LogTableModel()
        self.model.set_rows(list(self._log))
        container(self.instance.log).am_subscribe(self._on_new_logrecord)

    @property
    def _log(self):
        return container(self.instance.log)

    def close(self) -> None:
        self._log.am_unsubscribe(self._on_new_logrecord)

    @property
    def keymap(self) -> Keymap:
        return log_keymap()

    def clear_log(self) -> None:
        self._log.am_obj = []
        self._log.am_event()

    @staticmethod
    def copy(records: Sequence[LogRecord], whole: bool = True) -> str:
        """The text the copy actions put on the clipboard: whole lines, or only the messages."""
        lines = [record_line(r) if whole else str(r.content) for r in records]
        return os.linesep.join(lines)

    def copy_to_clipboard(self, text: str) -> None:  # pylint:disable=no-self-use
        GlobalInfo.ui_services.set_clipboard_text(text)

    def copy_selected(self, rows: Sequence[int]) -> None:
        self.copy_to_clipboard(self.copy(self.model.objects(rows), whole=True))

    def copy_selected_messages(self, rows: Sequence[int]) -> None:
        self.copy_to_clipboard(self.copy(self.model.objects(rows), whole=False))

    def copy_all(self) -> None:
        self.copy_to_clipboard(self.copy(self.model.log, whole=True))

    def copy_all_messages(self) -> None:
        self.copy_to_clipboard(self.copy(self.model.log, whole=False))

    def log_menu(self, rows: Sequence[int]) -> Menu:
        """The context menu: what LogMenu offers in the Qt view."""
        rows = list(rows)
        menu = Menu("")
        menu.add(MenuEntry("&Copy selected content", lambda: self.copy_selected_messages(rows), shortcut="Ctrl+C"))
        menu.add(MenuEntry("Copy selected message", lambda: self.copy_selected(rows)))
        menu.add(MenuEntry("Copy all content", self.copy_all_messages))
        menu.add(MenuEntry("Copy all messages", self.copy_all))
        menu.add(MenuSeparator())
        menu.add(MenuEntry("C&lear log", self.clear_log))
        return menu

    def _on_new_logrecord(self, log_record: LogRecord | None = None) -> None:
        gui_thread_schedule_async(self._on_new_logrecord_core, (log_record,))

    def _on_new_logrecord_core(self, log_record: LogRecord | None = None) -> None:
        if log_record is None:
            # reload
            self.model.set_rows(list(self._log))
        else:
            self.model.add_record(log_record)
