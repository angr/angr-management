import os
import logging
from typing import List, Any, Optional

import PySide2
from PySide2.QtWidgets import QTableView, QAbstractItemView, QHeaderView
from PySide2.QtCore import QAbstractTableModel, Qt
from PySide2.QtGui import QIcon

from ...config import IMG_LOCATION
from ...logic.threads import gui_thread_schedule
from ...data.log import LogRecord


class QLogIcons:
    BENCHMARK = QIcon(os.path.join(IMG_LOCATION, 'benchmark-icon.png'))
    WARNING = QIcon(os.path.join(IMG_LOCATION, 'warning-icon.png'))
    ERROR = QIcon(os.path.join(IMG_LOCATION, 'error-icon.png'))


class QLogItemModel(QAbstractTableModel):
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
        elif role == Qt.DecorationRole and col == QLogItemModel.COL_ICON:
            return self._get_column_icon(log)

        return None

    @staticmethod
    def _get_column_text(log: LogRecord, col: int) -> Any:
        mapping = {
            QLogItemModel.COL_TIMESTAMP: lambda x: str(x.timestamp),
            QLogItemModel.COL_SOURCE: lambda x: str(x.source),
            QLogItemModel.COL_CONTENT: lambda x: str(x.content),
        }
        func = mapping.get(col)
        if func is None:
            return None
        return func(log)

    @staticmethod
    def _get_column_icon(log: LogRecord) -> Optional[QIcon]:
        mapping = {
            1: QLogIcons.BENCHMARK,
            logging.WARNING: QLogIcons.WARNING,
            logging.ERROR: QLogIcons.ERROR,
            logging.CRITICAL: QLogIcons.ERROR,
        }
        return mapping.get(log.level, None)


class QLogWidget(QTableView):
    """
    Log table. Displays log messages.
    """

    def __init__(self, log_view, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.log_view = log_view

        hheader = self.horizontalHeader()
        vheader = self.verticalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)
        vheader.setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        vheader.setDefaultSectionSize(20)
        self.setShowGrid(False)

        self.model: QLogItemModel = QLogItemModel(self)

        # True if we want the log panel to automatically scroll to bottom
        self._auto_scroll: bool = True

        self.setModel(self.model)

        self.setColumnWidth(0, 20)
        hheader.setSectionResizeMode(1, QHeaderView.ResizeToContents)

        self.log_view.workspace.instance.log.am_subscribe(self._on_new_logrecord)

    def closeEvent(self, event):
        self.log_view.workspace.instance.log.am_unsubscribe(self._on_new_logrecord)
        super().closeEvent(event)

    def _on_new_logrecord(self, log_record: LogRecord=None):
        gui_thread_schedule(self._on_new_logrecord_core, (log_record, ))

    def _on_new_logrecord_core(self, log_record: LogRecord=None):
        self._before_row_insert()

        self.model.layoutAboutToBeChanged.emit()
        if log_record is None:
            # reload
            self.model._log = self.log_view.workspace.instance.log[::]
        else:
            self.model.log.append(log_record)
        self.model.layoutChanged.emit()

        self._after_row_insert()

    def _before_row_insert(self):
        scrollbar = self.verticalScrollBar()
        self._auto_scroll = scrollbar.value() == scrollbar.maximum()

    def _after_row_insert(self):
        if self._auto_scroll:
            self.scrollToBottom()
