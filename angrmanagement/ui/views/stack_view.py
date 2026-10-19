from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtGui import QCursor, QFont
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.data.breakpoint import BreakpointType
from angrmanagement.present.stack import StackPresenter, StackTableModel
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

from .view import InstanceView

if TYPE_CHECKING:
    import angr
    import PySide6
    from PySide6.QtWidgets import QMenu

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QStackTableModel(QtTableModelAdapter):
    """
    Stack table model: a Qt model over a :class:`~angrmanagement.present.stack.StackTableModel`.
    """

    Headers = StackTableModel.Headers
    COL_OFFSET = StackTableModel.COL_OFFSET
    COL_VALUE = StackTableModel.COL_VALUE

    table_model: StackTableModel

    def __init__(self, log_widget: QStackTableWidget | None = None, table_model: StackTableModel | None = None) -> None:
        super().__init__(table_model if table_model is not None else StackTableModel(), None, False)
        self._log_widget = log_widget

    @property
    def state(self) -> angr.SimState | None:
        return self.table_model.state

    @state.setter
    def state(self, state: angr.SimState | None) -> None:
        self.table_model.set_state(state)


class QStackTableWidget(QTableView):
    """
    Stack table widget.
    """

    def __init__(self, stack_view) -> None:
        super().__init__()
        self.stack_view = stack_view
        self.presenter: StackPresenter = stack_view.presenter

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QStackTableModel = QStackTableModel(self, self.presenter.model)
        self.setModel(self.model)

        font = QFont(Conf.disasm_font)
        self.setFont(font)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

    #
    # Events
    #

    def contextMenuEvent(self, _: PySide6.QtGui.QContextMenuEvent) -> None:
        if not self.selectedIndexes():
            return

        mnu = self._get_breakpoint_submenu()
        mnu.exec_(QCursor.pos())

    def _set_breakpoint(self, bp_type: BreakpointType = BreakpointType.Execute) -> None:
        """
        Set breakpoint at current cursor.
        """
        selected = self.selectedIndexes()
        if not selected:
            return
        self.presenter.set_breakpoint(selected[0].row(), bp_type)

    def _get_breakpoint_submenu(self) -> QMenu:
        """
        Get context menu to add new breakpoints.
        """
        selected = self.selectedIndexes()
        row = selected[0].row() if selected else 0
        return self.presenter.breakpoint_menu(row).qmenu(cached=False)


class StackView(InstanceView):
    """
    Stack table view.
    """

    presenter: StackPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "stack",
            workspace,
            default_docking_position,
            instance,
            StackPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "Stack"
        self._tbl_widget: QStackTableWidget | None = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 400
        self.updateGeometry()

    def reload(self) -> None:
        pass

    def closeEvent(self, event) -> None:
        self.presenter.close()
        super().closeEvent(event)

    @staticmethod
    def minimumSizeHint():
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        self._tbl_widget = QStackTableWidget(self)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
