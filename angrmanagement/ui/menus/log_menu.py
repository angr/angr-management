"""
The log view's context menu as a Qt menu.

Deprecated: the log view builds its menu with :meth:`angrmanagement.present.log.LogPresenter.log_menu`. This class
is kept so that code importing it keeps working.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.widgets.qlog_widget import QLogWidget


class LogMenu(Menu):
    """Copy and clear actions on ``log_widget``, which act on its selection when they run."""

    def __init__(self, log_widget: QLogWidget) -> None:
        super().__init__("", parent=log_widget)
        self.entries.extend(
            [
                MenuEntry("&Copy selected content", log_widget.copy_selected_messages, shortcut="Ctrl+C"),
                MenuEntry("Copy selected message", log_widget.copy_selected),
                MenuEntry("Copy all content", log_widget.copy_all_messages),
                MenuEntry("Copy all messages", log_widget.copy_all),
                MenuSeparator(),
                MenuEntry("C&lear log", log_widget.clear_log),
            ]
        )
