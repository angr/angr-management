from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QVBoxLayout

from angrmanagement.data.breakpoint import Breakpoint, BreakpointManager, BreakpointType
from angrmanagement.present.breakpoints import BreakpointsPresenter, BreakpointsTableModel
from angrmanagement.ui.dialogs import BreakpointDialog
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

from .view import InstanceView

if TYPE_CHECKING:
    from collections.abc import Sequence

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QBreakpointTableModel(QtTableModelAdapter):
    """
    Breakpoint table model: a Qt model over a :class:`~angrmanagement.present.breakpoints.BreakpointsTableModel`.
    """

    Headers = BreakpointsTableModel.Headers
    COL_TYPE = BreakpointsTableModel.COL_TYPE
    COL_ADDR = BreakpointsTableModel.COL_ADDR
    COL_SIZE = BreakpointsTableModel.COL_SIZE
    COL_COMMENT = BreakpointsTableModel.COL_COMMENT

    table_model: BreakpointsTableModel

    def __init__(self, breakpoint_mgr: BreakpointManager, table_model: BreakpointsTableModel | None = None) -> None:
        super().__init__(table_model if table_model is not None else BreakpointsTableModel(breakpoint_mgr), None, False)
        self.breakpoint_mgr = breakpoint_mgr
        self._owns_table_model = table_model is None

    def shutdown(self) -> None:
        if self._owns_table_model:
            self.table_model.shutdown()


class QBreakpointTableWidget(QTableView):
    """
    Breakpoint table widget.
    """

    def __init__(
        self, breakpoint_mgr: BreakpointManager, workspace: Workspace, presenter: BreakpointsPresenter | None = None
    ) -> None:
        super().__init__()
        self.workspace = workspace
        self.breakpoint_mgr = breakpoint_mgr
        self.presenter = presenter

        hheader = self.horizontalHeader()
        hheader.setVisible(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QBreakpointTableModel = QBreakpointTableModel(
            self.breakpoint_mgr, presenter.model if presenter is not None else None
        )
        self.setModel(self.model)

        for col in range(len(QBreakpointTableModel.Headers)):
            hheader.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        hheader.setStretchLastSection(True)
        self.doubleClicked.connect(self._on_cell_double_click)

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self.model.shutdown()
        super().closeEvent(event)

    def _selected_breakpoints(self) -> list[Breakpoint]:
        return self.model.table_model.objects(i.row() for i in self.selectedIndexes())

    def contextMenuEvent(self, event) -> None:
        breakpoints = self._selected_breakpoints()
        if self.presenter is not None:
            menu = self.presenter.breakpoints_menu(breakpoints, edit=self.edit_breakpoint, new=self.new_breakpoint)
            menu.qmenu(cached=False).exec_(event.globalPos())

    def _on_cell_double_click(self, index) -> None:
        bp = self.model.table_model.row(index.row())
        if bp is not None:
            self.edit_breakpoint(bp)

    def new_breakpoint(self) -> None:
        bp = Breakpoint(BreakpointType.Execute, 0)
        if BreakpointDialog(bp, self.workspace, self).exec_():
            self.breakpoint_mgr.add_breakpoint(bp)

    def edit_breakpoint(self, breakpoint_: Breakpoint) -> None:
        BreakpointDialog(breakpoint_, self.workspace, self).exec_()

    def remove_breakpoints(self, breakpoints: Sequence[Breakpoint]) -> None:
        for b in breakpoints:
            self.breakpoint_mgr.remove_breakpoint(b)


class BreakpointsView(InstanceView):
    """
    Breakpoints table view.
    """

    presenter: BreakpointsPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "breakpoints",
            workspace,
            default_docking_position,
            instance,
            BreakpointsPresenter(workspace, instance, default_docking_position),
        )
        self.base_caption = "Breakpoints"
        self._tbl_widget: QBreakpointTableWidget | None = None
        self._init_widgets()
        self.reload()

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
        self._tbl_widget = QBreakpointTableWidget(self.instance.breakpoint_mgr, self.workspace, self.presenter)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
