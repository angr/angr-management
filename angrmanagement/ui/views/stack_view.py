import logging
from typing import Any, Optional

import PySide2
from PySide2.QtGui import QFont
from PySide2.QtCore import QAbstractTableModel, Qt, QSize
from PySide2.QtWidgets import QTableView, QAbstractItemView, QHeaderView, QVBoxLayout

import angr

from ...logic.debugger import DebuggerWatcher
from ...config import Conf
from .view import BaseView


_l = logging.getLogger(name=__name__)


class QStackTableModel(QAbstractTableModel):
    """
    Stack table model.
    """

    Headers = ['Offset', 'Value']
    COL_REGISTER = 0
    COL_VALUE = 1

    def __init__(self, log_widget: 'QStackTableWidget' = None):
        super().__init__()
        self._log_widget = log_widget
        self.state: angr.SimState = None

    def rowCount(self, parent:PySide2.QtCore.QModelIndex=...) -> int:  # pylint:disable=unused-argument
        return 0 if self.state is None else 15

    def columnCount(self, parent:PySide2.QtCore.QModelIndex=...) -> int:  # pylint:disable=unused-argument
        return len(self.Headers)

    def headerData(self, section:int, orientation:PySide2.QtCore.Qt.Orientation, role:int=...) -> Any:  # pylint:disable=unused-argument
        if role != Qt.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index:PySide2.QtCore.QModelIndex, role:int=...) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if role == Qt.DisplayRole:
            return self._get_column_text(row, col)
        else:
            return None

    def _get_column_text(self, row, col: int) -> Any:
        width = self.state.arch.bits // 8
        offset = row * width
        mapping = {
            QStackTableModel.COL_REGISTER: lambda x: str(offset),
            QStackTableModel.COL_VALUE: lambda x: repr(self.state.stack_read(offset, width)),
        }
        func = mapping.get(col)
        if func is None:
            return None
        return func(row)


class QStackTableWidget(QTableView):
    """
    Stack table widget.
    """

    def __init__(self, stack_view, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stack_view = stack_view

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)

        self.model: QStackTableModel = QStackTableModel(self)
        self.setModel(self.model)

        font = QFont(Conf.disasm_font)
        self.setFont(font)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeToContents)

        self._dbg_manager = stack_view.workspace.instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    #
    # Events
    #

    def closeEvent(self, event):
        self._dbg_watcher.shutdown()
        super().closeEvent(event)

    def _on_debugger_state_updated(self):
        dbg = self._dbg_manager.debugger
        self.model.state = None if dbg.am_none else dbg.simstate
        self.model.layoutChanged.emit()
        self.update()


class StackView(BaseView):
    """
    Stack table view.
    """

    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super().__init__('stack', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Stack'
        self._tbl_widget: Optional[QStackTableWidget] = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 400
        self.updateGeometry()

    def reload(self):
        pass

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint:disable=unused-argument
        return QSize(200, 200)

    def _init_widgets(self):
        vlayout = QVBoxLayout()
        self._tbl_widget = QStackTableWidget(self)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
