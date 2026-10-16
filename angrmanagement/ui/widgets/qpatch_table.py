from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QContextMenuEvent, QCursor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.present.patches import PatchesPresenter, PatchesTableModel, PatchRow

from .qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    from angr.knowledge_plugins.patches import Patch
    from PySide6.QtGui import QCloseEvent

    from angrmanagement.data.instance import Instance


#: A row of the patch table; the name the QTableWidget-based table used.
QPatchTableItem = PatchRow


class QPatchTable(QTableView):
    """
    Table of all patches, over a :class:`~angrmanagement.present.patches.PatchesTableModel`; comments are editable.
    """

    HEADER = PatchesTableModel.HEADER

    def __init__(self, instance: Instance, parent, presenter: PatchesPresenter | None = None) -> None:
        super().__init__(parent)

        self.instance = instance
        # the table closes a presenter it made itself; a view closes its own
        self._owns_presenter = presenter is None
        self.presenter = presenter if presenter is not None else PatchesPresenter(None, instance)
        self._model = QtTableModelAdapter(self.presenter.model, self, use_table_font=False)
        self.setModel(self._model)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.verticalHeader().setVisible(False)
        self.reload()

    @property
    def items(self) -> list[PatchRow]:
        return self.presenter.model.rows

    def rowCount(self) -> int:
        return self._model.rowCount()

    def reload(self) -> None:
        self.presenter.reload()

    def get_selected_patches(self) -> set[Patch]:
        """
        Get the set of selected patches.
        """
        return self.presenter.model.patches({idx.row() for idx in self.selectedIndexes()})

    def revert_selected_patches(self) -> None:
        """
        Revert any selected patches.
        """
        self.presenter.revert(self.get_selected_patches())

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:  # pylint: disable=unused-argument
        """
        Display view context menu.
        """
        self.presenter.patches_menu(self.get_selected_patches()).qmenu(cached=False).exec_(QCursor.pos())

    def closeEvent(self, event: QCloseEvent) -> None:  # pylint:disable=unused-argument
        if self._owns_presenter:
            self.presenter.close()
