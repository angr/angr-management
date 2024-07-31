from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QSize, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QTableView, QVBoxLayout

from .view import InstanceView

if TYPE_CHECKING:
    import PySide6

    from angrmanagement.data.instance import Instance
    from angrmanagement.data.trace import Trace
    from angrmanagement.ui.workspace import Workspace


class QTraceTableModel(QAbstractTableModel):
    """
    Trace table model.
    """

    Headers = ["Source"]
    COL_SOURCE = 0

    def __init__(self, instance: Instance) -> None:
        super().__init__()
        self.instance = instance
        self.instance.current_trace.am_subscribe(self._on_traces_updated)
        self.instance.traces.am_subscribe(self._on_traces_updated)

    def shutdown(self) -> None:
        self.instance.current_trace.am_unsubscribe(self._on_traces_updated)
        self.instance.traces.am_unsubscribe(self._on_traces_updated)

    def _on_traces_updated(self, **kwargs) -> None:  # pylint:disable=unused-argument
        self.beginResetModel()
        self.endResetModel()

    def rowCount(self, parent: PySide6.QtCore.QModelIndex = ...) -> int:  # pylint:disable=unused-argument
        return len(self.instance.traces)

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
        if row >= len(self.instance.traces):
            return None
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._get_column_text(self.instance.traces[row], col)
        else:
            return None

    def _get_column_text(self, trace: Trace, col: int) -> Any:
        if col == QTraceTableModel.COL_SOURCE:
            return trace.source + (" (Current)" if self.instance.current_trace.am_obj is trace else "")
        else:
            return None


class QTraceTableWidget(QTableView):
    """
    Trace table widget.
    """

    def __init__(self, instance: Instance, parent=None) -> None:
        super().__init__(parent=parent)
        self.instance = instance

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QTraceTableModel = QTraceTableModel(instance)
        self.setModel(self.model)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

    #
    # Events
    #

    def closeEvent(self, event) -> None:
        self.model.shutdown()
        super().closeEvent(event)

    def contextMenuEvent(self, event) -> None:
        selected_rows = {i.row() for i in self.selectedIndexes()}
        traces = [self.instance.traces[r] for r in selected_rows]
        if len(traces):
            menu = QMenu("", self)
            if len(traces) == 1 and not self.workspace(traces[0]):
                menu.addAction("Use as current trace", lambda: self.workspace.set_current_trace(traces[0]))

            def remove_selected_traces() -> None:
                for t in traces:
                    self.workspace.remove_trace(t)

            menu.addAction("Remove trace" + ("s" if len(traces) > 1 else ""), remove_selected_traces)
            menu.exec_(event.globalPos())


class TracesView(InstanceView):
    """
    Traces table view.
    """

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("traces", workspace, default_docking_position, instance)

        self.base_caption = "Traces"
        self._tbl_widget: QTraceTableWidget | None = None
        self._init_widgets()
        self.reload()

    def reload(self) -> None:
        pass

    @staticmethod
    def minimumSizeHint():
        return QSize(200, 200)

    def _init_widgets(self) -> None:
        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        self._tbl_widget = QTraceTableWidget(self.instance, self)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
