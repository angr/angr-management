from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.present.registers import RegistersPresenter, RegistersTableModel
from angrmanagement.ui.widgets.qt_table import QtTableModelAdapter

from .view import InstanceView

if TYPE_CHECKING:
    import angr

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class QRegisterTableModel(QtTableModelAdapter):
    """
    Register table model: a Qt model over a :class:`~angrmanagement.present.registers.RegistersTableModel`.
    """

    Headers = RegistersTableModel.Headers
    COL_REGISTER = RegistersTableModel.COL_REGISTER
    COL_VALUE = RegistersTableModel.COL_VALUE

    table_model: RegistersTableModel

    def __init__(self, log_widget: QRegisterTableWidget | None = None, table_model: RegistersTableModel | None = None):
        super().__init__(table_model if table_model is not None else RegistersTableModel(), None, False)
        self._log_widget = log_widget

    @property
    def state(self) -> angr.SimState | None:
        return self.table_model.state

    def update_state(self, state) -> None:
        self.table_model.update_state(state)


class QRegisterTableWidget(QTableView):
    """
    Register table widget.
    """

    def __init__(self, register_view) -> None:
        super().__init__()
        self.register_view = register_view
        self.presenter: RegistersPresenter = register_view.presenter

        hheader = self.horizontalHeader()
        hheader.setVisible(True)
        hheader.setStretchLastSection(True)

        vheader = self.verticalHeader()
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.model: QRegisterTableModel = QRegisterTableModel(self, self.presenter.model)
        self.setModel(self.model)

        font = QFont(Conf.disasm_font)
        self.setFont(font)

        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)


class RegistersView(InstanceView):
    """
    Register table view.
    """

    presenter: RegistersPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "registers",
            workspace,
            default_docking_position,
            instance,
            RegistersPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "Registers"
        self._tbl_widget: QRegisterTableWidget | None = None
        self._init_widgets()
        self.reload()

        self.width_hint = 500
        self.height_hint = 0
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
        self._tbl_widget = QRegisterTableWidget(self)
        vlayout.addWidget(self._tbl_widget)
        self.setLayout(vlayout)
