# pylint:disable=unused-argument
import os
import logging
from typing import List, Any, Optional

import PySide2
from PySide2.QtWidgets import QTableView, QAbstractItemView, QHeaderView
from PySide2.QtCore import QAbstractTableModel, Qt
from PySide2.QtGui import QIcon, QCursor, QGuiApplication, QClipboard, QKeySequence

from ...config import IMG_LOCATION
from ...logic.threads import gui_thread_schedule_async
from ...data.log import LogRecord
from ..menus.log_menu import LogMenu


class QLogIcons:
    """
    All icons that are used in the log table.
    """

    BENCHMARK = None
    WARNING = None
    ERROR = None

    @classmethod
    def benchmark(cls) -> QIcon:
        if cls.BENCHMARK is None:
            cls.BENCHMARK = QIcon(os.path.join(IMG_LOCATION, 'benchmark-icon.png'))
        return cls.BENCHMARK

    @classmethod
    def warning(cls) -> QIcon:
        if cls.WARNING is None:
            cls.WARNING = QIcon(os.path.join(IMG_LOCATION, 'warning-icon.png'))
        return cls.WARNING

    @classmethod
    def error(cls) -> QIcon:
        if cls.ERROR is None:
            cls.ERROR = QIcon(os.path.join(IMG_LOCATION, 'error-icon.png'))
        return cls.ERROR


class QLogTableModel(QAbstractTableModel):
    """
    Implements a table model for log items.
    """

    Headers = ["", "Timestamp", "Source", "Content"]
    COL_ICON = 0
    COL_TIMESTAMP = 1
    COL_SOURCE = 2
    COL_CONTENT = 3

    def __init__(self, log_widget: 'QLogWidget'=None):
        super().__init__()
        self._log_widget = log_widget
        self._log: List[LogRecord] = [ ]

    @property
    def log(self) -> List[LogRecord]:
        return self._log

    def rowCount(self, parent:PySide2.QtCore.QModelIndex=...) -> int:
        return len(self._log)

    def columnCount(self, parent:PySide2.QtCore.QModelIndex=...) -> int:
        return len(self.Headers)

    def headerData(self, section:int, orientation:PySide2.QtCore.Qt.Orientation, role:int=...) -> Any:
        if role != Qt.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index:PySide2.QtCore.QModelIndex, role:int=...) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        if row >= len(self.log):
            return None
        log = self.log[row]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._get_column_text(log, col)
        elif role == Qt.DecorationRole and col == QLogTableModel.COL_ICON:
            return self._get_column_icon(log)

        return None

    @staticmethod
    def _get_column_text(log: LogRecord, col: int) -> Any:
        mapping = {
            QLogTableModel.COL_TIMESTAMP: lambda x: str(x.timestamp),
            QLogTableModel.COL_SOURCE: lambda x: str(x.source),
            QLogTableModel.COL_CONTENT: lambda x: str(x.content),
        }
        func = mapping.get(col)
        if func is None:
            return None
        return func(log)

    @staticmethod
    def _get_column_icon(log: LogRecord) -> Optional[QIcon]:
        mapping = {
            1: QLogIcons.benchmark(),
            logging.WARNING: QLogIcons.warning(),
            logging.ERROR: QLogIcons.error(),
            logging.CRITICAL: QLogIcons.error(),
        }
        return mapping.get(log.level, None)

    @staticmethod
    def level_to_text(loglevel: int) -> str:
        mapping = {
            1: "BENCHMARK",
            logging.DEBUG: "DEBUG",
            logging.INFO: "INFO",
            logging.WARNING: "WARNING",
            logging.ERROR: "ERROR",
            logging.CRITICAL: "CRITICAL",
        }
        return mapping.get(loglevel, "")


class QLogWidget(QTableView):
    """
    Log table. Displays log messages.
    """

    def __init__(self, log_view, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.log_view = log_view
        # True if we want the log panel to automatically scroll to bottom
        self._auto_scroll: bool = True
        self._context_menu = LogMenu(self).qmenu()

        hheader = self.horizontalHeader()
        vheader = self.verticalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)
        vheader.setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        vheader.setDefaultSectionSize(20)
        self.setShowGrid(False)

        self.model: QLogTableModel = QLogTableModel(self)

        self.setModel(self.model)

        self.setColumnWidth(0, 20)
        hheader.setSectionResizeMode(1, QHeaderView.ResizeToContents)

        self.log_view.workspace.instance.log.am_subscribe(self._on_new_logrecord)

    #
    # Public methods
    #

    def clear_log(self):
        self.log_view.workspace.instance.log.am_obj = [ ]
        self.log_view.workspace.instance.log.am_event()

    def copy_selected(self):
        content = [ ]
        selection = self.selectionModel().selectedRows()
        for row_index in selection:
            record = self.model.log[row_index.row()]
            content.append("%s | %s | %s | %s" % (
                QLogTableModel.level_to_text(record.level),
                str(record.timestamp),
                record.source,
                record.content
            ))
        self._copy_to_clipboard(os.linesep.join(content))

    def copy_selected_messages(self):
        content = [ ]
        selection = self.selectionModel().selectedRows()
        for row_index in selection:
            content.append(self.model.log[row_index.row()].content)
        self._copy_to_clipboard(os.linesep.join(content))

    def copy_all(self):
        content = [ ]
        for record in self.model.log:
            content.append("%s | %s | %s | %s" % (
                QLogTableModel.level_to_text(record.level),
                str(record.timestamp),
                record.source,
                record.content
            ))
        self._copy_to_clipboard(os.linesep.join(content))

    def copy_all_messages(self):
        content = [record.content for record in self.model.log]
        self._copy_to_clipboard(os.linesep.join(content))

    #
    # Events
    #

    def closeEvent(self, event):
        self.log_view.workspace.instance.log.am_unsubscribe(self._on_new_logrecord)
        super().closeEvent(event)

    def contextMenuEvent(self, arg__1: PySide2.QtGui.QContextMenuEvent):
        self._context_menu.popup(QCursor.pos())

    def _on_new_logrecord(self, log_record: LogRecord = None):
        gui_thread_schedule_async(self._on_new_logrecord_core, (log_record,))

    def _on_new_logrecord_core(self, log_record: LogRecord = None):
        self._before_row_insert()

        if log_record is None:
            # reload
            self.model.layoutAboutToBeChanged.emit()
            self.model._log = self.log_view.workspace.instance.log[::]
            self.model.layoutChanged.emit()
        else:
            log_records = len(self.model.log)
            self.model.rowsAboutToBeInserted.emit(self, log_records, log_records)
            self.model.log.append(log_record)
            self.model.rowsInserted.emit(self, log_records, log_records)

        self._after_row_insert()

    def _before_row_insert(self):
        scrollbar = self.verticalScrollBar()
        self._auto_scroll = scrollbar.value() == scrollbar.maximum()

    def _after_row_insert(self):
        if self._auto_scroll:
            self.scrollToBottom()

    def keyPressEvent(self, event:PySide2.QtGui.QKeyEvent):
        if event.matches(QKeySequence.Copy):
            self.copy_selected_messages()
        else:
            super().keyPressEvent(event)

    #
    # Private methods
    #

    @staticmethod
    def _copy_to_clipboard(content: str) -> None:
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(content, QClipboard.Clipboard)
        if clipboard.supportsSelection():
            clipboard.setText(content, QClipboard.Selection)
