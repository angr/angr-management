# pylint:disable=unused-argument
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QClipboard, QCursor, QGuiApplication, QIcon, QKeySequence
from PySide6.QtWidgets import QAbstractItemView, QTableView

from angrmanagement.consts import IMG_LOCATION
from angrmanagement.present.log import BENCHMARK_LEVEL, LogPresenter, LogTableModel, record_line
from angrmanagement.present.log import level_to_text as _level_to_text
from angrmanagement.ui.menus.log_menu import LogMenu

from .qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    import PySide6

    from angrmanagement.data.log import LogRecord


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
            cls.BENCHMARK = QIcon(os.path.join(IMG_LOCATION, "benchmark-icon.png"))
        return cls.BENCHMARK

    @classmethod
    def warning(cls) -> QIcon:
        if cls.WARNING is None:
            cls.WARNING = QIcon(os.path.join(IMG_LOCATION, "warning-icon.png"))
        return cls.WARNING

    @classmethod
    def error(cls) -> QIcon:
        if cls.ERROR is None:
            cls.ERROR = QIcon(os.path.join(IMG_LOCATION, "error-icon.png"))
        return cls.ERROR


class QLogTableModel(QtTableModelAdapter):
    """
    Qt model over a :class:`~angrmanagement.present.log.LogTableModel`; the first column shows the level's icon.
    """

    Headers = LogTableModel.Headers
    COL_ICON = LogTableModel.COL_ICON
    COL_TIMESTAMP = LogTableModel.COL_TIMESTAMP
    COL_SOURCE = LogTableModel.COL_SOURCE
    COL_CONTENT = LogTableModel.COL_CONTENT

    table_model: LogTableModel

    def __init__(self, log_widget: QLogWidget | None = None, log_model: LogTableModel | None = None) -> None:
        super().__init__(log_model if log_model is not None else LogTableModel(), use_table_font=False)
        self._log_widget = log_widget

    @property
    def log(self) -> list[LogRecord]:
        return self.table_model.log

    def data(self, index, role=None) -> Any:
        if not index.isValid():
            return None
        col = index.column()
        if role == Qt.ItemDataRole.DecorationRole and col == self.COL_ICON:
            record = self.table_model.row(index.row())
            return self._get_column_icon(record) if record is not None else None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft
        if role == Qt.ItemDataRole.DisplayRole and col == self.COL_ICON:
            # the icon says it
            return None
        if role in (Qt.ItemDataRole.ForegroundRole, Qt.ItemDataRole.ToolTipRole):
            return None
        return super().data(index, role)

    @staticmethod
    def _get_column_text(log: LogRecord, col: int) -> Any:
        if col == LogTableModel.COL_ICON:
            return None
        return LogTableModel().column_text(log, col)

    @staticmethod
    def _get_column_icon(log: LogRecord) -> QIcon | None:
        mapping = {
            BENCHMARK_LEVEL: QLogIcons.benchmark(),
            logging.WARNING: QLogIcons.warning(),
            logging.ERROR: QLogIcons.error(),
            logging.CRITICAL: QLogIcons.error(),
        }
        return mapping.get(log.level)

    @staticmethod
    def level_to_text(loglevel: int) -> str:
        return _level_to_text(loglevel)

    def add_record(self, log_record: LogRecord) -> None:
        self.table_model.add_record(log_record)


class QLogWidget(QTableView):
    """
    Log table. Displays log messages.
    """

    def __init__(self, log_view, presenter: LogPresenter | None = None) -> None:
        super().__init__()

        self.log_view = log_view
        self._owns_presenter = presenter is None
        self.presenter = presenter if presenter is not None else LogPresenter(log_view.workspace, log_view.instance)
        # True if we want the log panel to automatically scroll to bottom
        self._auto_scroll: bool = True
        self._context_menu = LogMenu(self).qmenu()

        hheader = self.horizontalHeader()
        vheader = self.verticalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)
        vheader.setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        vheader.setDefaultSectionSize(20)
        self.setShowGrid(False)

        self.model: QLogTableModel = QLogTableModel(self, self.presenter.model)

        self.setModel(self.model)

        self.setColumnWidth(0, 20)
        self.setColumnWidth(1, 150)

        self.doubleClicked.connect(self._on_double_clicked)

        self.presenter.model.about_to_change.connect(self._before_row_insert)
        self.presenter.model.changed.connect(self._after_row_insert)

    #
    # Public methods
    #

    def clear_log(self) -> None:
        self.presenter.clear_log()

    def _selected_rows(self) -> list[int]:
        return [index.row() for index in self.selectionModel().selectedRows()]

    def copy_selected(self) -> None:
        self._copy_to_clipboard(
            os.linesep.join(record_line(r) for r in self.presenter.model.objects(self._selected_rows()))
        )

    def copy_selected_messages(self) -> None:
        records = self.presenter.model.objects(self._selected_rows())
        self._copy_to_clipboard(os.linesep.join(str(r.content) for r in records))

    def copy_all(self) -> None:
        self._copy_to_clipboard(os.linesep.join(record_line(r) for r in self.presenter.model.log))

    def copy_all_messages(self) -> None:
        self._copy_to_clipboard(os.linesep.join(str(r.content) for r in self.presenter.model.log))

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self.presenter.model.about_to_change.disconnect(self._before_row_insert)
        self.presenter.model.changed.disconnect(self._after_row_insert)
        if self._owns_presenter:
            self.presenter.close()
        super().closeEvent(event)

    def contextMenuEvent(self, _: PySide6.QtGui.QContextMenuEvent) -> None:
        self._context_menu.popup(QCursor.pos())

    def _on_new_logrecord(self, log_record: LogRecord = None) -> None:
        self.presenter._on_new_logrecord(log_record)  # pylint:disable=protected-access

    def _on_new_logrecord_core(self, log_record: LogRecord = None) -> None:
        self.presenter._on_new_logrecord_core(log_record)  # pylint:disable=protected-access

    def _before_row_insert(self, *_args) -> None:
        scrollbar = self.verticalScrollBar()
        self._auto_scroll = scrollbar.value() == scrollbar.maximum()

    def _after_row_insert(self, *_args) -> None:
        if self._auto_scroll:
            self.scrollToBottom()

    def keyPressEvent(self, event: PySide6.QtGui.QKeyEvent) -> None:
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_selected_messages()
        else:
            super().keyPressEvent(event)

    def _on_double_clicked(self, item) -> None:
        # Expand/collapse row
        if self.rowHeight(item.row()) > 20:
            self.setRowHeight(item.row(), 20)
        else:
            self.setRowHeight(item.row(), self.sizeHintForRow(item.row()))

    #
    # Private methods
    #

    @staticmethod
    def _copy_to_clipboard(content: str) -> None:
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(content, QClipboard.Mode.Clipboard)
        if clipboard.supportsSelection():
            clipboard.setText(content, QClipboard.Mode.Selection)
