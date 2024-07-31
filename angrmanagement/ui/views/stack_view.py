from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QSize, Qt
from PySide6.QtGui import QAction, QCursor, QFont
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QTableView, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.logic.debugger import DebuggerWatcher

from .view import InstanceView

if TYPE_CHECKING:
    import angr
    import PySide6

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QStackTableModel(QAbstractTableModel):
    """
    Stack table model.
    """

    Headers = ["Offset", "Value"]
    COL_OFFSET = 0
    COL_VALUE = 1

    def __init__(self, log_widget: QStackTableWidget = None) -> None:
        super().__init__()
        self._log_widget = log_widget
        self.state: angr.SimState = None

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return 0 if self.state is None else 15

    def columnCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self.Headers)

    def headerData(
        self, section: int, orientation: PySide6.QtCore.Qt.Orientation, role: int = ...
    ) -> Any:  # pylint:disable=unused-argument
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if section < len(self.Headers):
            return self.Headers[section]
        return None

    def data(self, index: PySide6.QtCore.QModelIndex, role: int = ...) -> Any:
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_column_text(row, col)
        else:
            return None

    def _get_column_text(self, row, col: int) -> Any:
        width = self.state.arch.bits // 8
        offset = row * width
        mapping = {
            QStackTableModel.COL_OFFSET: lambda x: str(offset),
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

    def __init__(self, stack_view) -> None:
        super().__init__()
        self.stack_view = stack_view

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QStackTableModel = QStackTableModel(self)
        self.setModel(self.model)

        font = QFont(Conf.disasm_font)
        self.setFont(font)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

        self._dbg_manager = stack_view.instance.debugger_mgr
        self._dbg_watcher = DebuggerWatcher(self._on_debugger_state_updated, self._dbg_manager.debugger)
        self._on_debugger_state_updated()

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self._dbg_watcher.shutdown()
        super().closeEvent(event)

    def _on_debugger_state_updated(self) -> None:
        dbg = self._dbg_manager.debugger
        self.model.state = None if dbg.am_none else dbg.simstate
        self.model.layoutChanged.emit()

    def contextMenuEvent(self, arg__1: PySide6.QtGui.QContextMenuEvent) -> None:  # pylint:disable=unused-argument
        if not self.selectedIndexes():
            return

        mnu = self._get_breakpoint_submenu()
        mnu.exec_(QCursor.pos())

    def _set_breakpoint(self, bp_type: BreakpointType = BreakpointType.Execute) -> None:
        """
        Set breakpoint at current cursor.
        """
        state = self.model.state
        if state is None or not state.regs.sp.concrete:
            return

        selected = self.selectedIndexes()
        if not selected:
            return

        row = selected[0].row()
        width = state.arch.bits // 8
        offset = row * width + state.solver.eval(state.regs.sp)
        self.stack_view.instance.breakpoint_mgr.add_breakpoint(Breakpoint(bp_type, offset, width))

    def _get_breakpoint_submenu(self) -> QMenu:
        """
        Get context menu to add new breakpoints.
        """
        mnu = QMenu("Set &breakpoint", self)
        act = QAction("Break on &Execute", mnu)
        act.triggered.connect(functools.partial(self._set_breakpoint, BreakpointType.Execute))
        mnu.addAction(act)
        act = QAction("Break on &Read", mnu)
        act.triggered.connect(functools.partial(self._set_breakpoint, BreakpointType.Read))
        mnu.addAction(act)
        act = QAction("Break on &Write", mnu)
        act.triggered.connect(functools.partial(self._set_breakpoint, BreakpointType.Write))
        mnu.addAction(act)
        return mnu


class StackView(InstanceView):
    """
    Stack table view.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("stack", workspace, default_docking_position, instance)

        self.base_caption = "Stack"
        self._tbl_widget: QStackTableWidget | None = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 400
        self.updateGeometry()

    def reload(self) -> None:
        pass

    @staticmethod
    def minimumSizeHint():
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        self._tbl_widget = QStackTableWidget(self)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
