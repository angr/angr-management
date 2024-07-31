from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QSize, Qt
from PySide6.QtGui import QBrush, QFont
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.logic.debugger import DebuggerWatcher

from .view import InstanceView

if TYPE_CHECKING:
    import angr
    import PySide6
    from archinfo import Register

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QRegisterTableModel(QAbstractTableModel):
    """
    Register table model.
    """

    Headers = ["Name", "Value"]
    COL_REGISTER = 0
    COL_VALUE = 1

    def __init__(self, log_widget: QRegisterTableWidget = None) -> None:
        super().__init__()
        self._log_widget = log_widget
        self.state: angr.SimState = None
        self._last_state: angr.SimState = None

    def _filtered_register_list(self):
        return [reg for reg in self.state.arch.register_list if reg.general_purpose]

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return 0 if self.state is None else len(self._filtered_register_list())

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
        reg = self._filtered_register_list()[row]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_column_text(reg, col)
        elif role == Qt.ItemDataRole.ForegroundRole:
            return QBrush(Qt.GlobalColor.red) if self._did_data_change(reg) else None
        else:
            return None

    def _get_column_text(self, reg: Register, col: int) -> Any:
        mapping = {
            QRegisterTableModel.COL_REGISTER: lambda x: x.name,
            QRegisterTableModel.COL_VALUE: lambda x: repr(self.state.regs.get(x.name)),
        }
        func = mapping.get(col)
        if func is None:
            return None
        return func(reg)

    def _did_data_change(self, reg: Register) -> bool:
        if self._last_state is None:
            return False
        different = self.state.solver.eval(self.state.regs.get(reg.name) != self._last_state.regs.get(reg.name))
        return different

    def update_state(self, state) -> None:
        self._last_state = self.state.copy() if self.state else None
        self.state = None if state is None else state


class QRegisterTableWidget(QTableView):
    """
    Register table widget.
    """

    def __init__(self, register_view) -> None:
        super().__init__()
        self.register_view = register_view

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QRegisterTableModel = QRegisterTableModel(self)
        self.setModel(self.model)

        font = QFont(Conf.disasm_font)
        self.setFont(font)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

        self._dbg_manager = register_view.instance.debugger_mgr
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
        self.model.update_state(None if dbg.am_none else dbg.simstate)
        self.model.layoutChanged.emit()


class RegistersView(InstanceView):
    """
    Register table view.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("registers", workspace, default_docking_position, instance)

        self.base_caption = "Registers"
        self._tbl_widget: QRegisterTableWidget | None = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 0
        self.updateGeometry()

    def reload(self) -> None:
        pass

    @staticmethod
    def minimumSizeHint():
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        self._tbl_widget = QRegisterTableWidget(self)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
