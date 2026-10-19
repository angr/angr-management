from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QVBoxLayout

from angrmanagement.present.traces import TracesPresenter, TracesTableModel
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QTraceTableModel(QtTableModelAdapter):
    """
    Trace table model: a Qt model over a :class:`~angrmanagement.present.traces.TracesTableModel`.
    """

    Headers = TracesTableModel.Headers
    COL_SOURCE = TracesTableModel.COL_SOURCE

    table_model: TracesTableModel

    def __init__(self, instance: Instance, table_model: TracesTableModel | None = None) -> None:
        super().__init__(table_model if table_model is not None else TracesTableModel(instance), None, False)
        self.instance = instance
        self._owns_table_model = table_model is None

    def shutdown(self) -> None:
        if self._owns_table_model:
            self.table_model.shutdown()


class QTraceTableWidget(QTableView):
    """
    Trace table widget.
    """

    def __init__(self, instance: Instance, parent=None, presenter: TracesPresenter | None = None) -> None:
        super().__init__(parent=parent)
        self.instance = instance
        self.presenter = presenter

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QTraceTableModel = QTraceTableModel(instance, presenter.model if presenter is not None else None)
        self.setModel(self.model)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self.model.shutdown()
        super().closeEvent(event)

    def contextMenuEvent(self, event) -> None:
        if self.presenter is None:
            return
        rows = [i.row() for i in self.selectedIndexes()]
        menu = self.presenter.traces_menu(self.model.table_model.objects(rows))
        if menu is not None:
            menu.qmenu(cached=False).exec_(event.globalPos())


class TracesView(InstanceView):
    """
    Traces table view.
    """

    presenter: TracesPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "traces",
            workspace,
            default_docking_position,
            instance,
            TracesPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "Traces"
        self._tbl_widget: QTraceTableWidget | None = None
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
        vlayout.setContentsMargins(0, 0, 0, 0)
        self._tbl_widget = QTraceTableWidget(self.instance, self, self.presenter)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
