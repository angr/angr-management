from typing import TYPE_CHECKING

from PySide2.QtGui import QKeySequence, Qt

from .menu import Menu, MenuEntry, MenuSeparator

if TYPE_CHECKING:
    from angrmanagement.ui.widgets.qlog_widget import QLogWidget


class LogMenu(Menu):
    def __init__(self, log_widget: 'QLogWidget'):
        super().__init__("", parent=log_widget)

        self.entries.extend([
            MenuEntry('&Copy selected content', log_widget.copy_selected_messages,
                      shortcut=QKeySequence(Qt.CTRL + Qt.Key_C)),
            MenuEntry('Copy selected message', log_widget.copy_selected),
            MenuEntry('Copy all content', log_widget.copy_all_messages),
            MenuEntry('Copy all messages', log_widget.copy_all),
            MenuSeparator(),
            MenuEntry('C&lear log', log_widget.clear_log),
        ])
