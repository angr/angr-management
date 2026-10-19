from __future__ import annotations

import re
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.present.strings import StringsTableModel
from angrmanagement.ui.dialogs.xref import XRefDialog

from .qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData
    from PySide6.QtGui import QKeyEvent

    from angrmanagement.data.instance import Instance


class QStringModel(QtTableModelAdapter):
    """
    Qt model over a :class:`~angrmanagement.present.strings.StringsTableModel`, which lists, sorts and filters.
    """

    HEADER = StringsTableModel.HEADER

    ADDRESS_COL = StringsTableModel.ADDRESS_COL
    SIZE_COL = StringsTableModel.SIZE_COL
    LENGTH_COL = StringsTableModel.LENGTH_COL
    STRING_COL = StringsTableModel.STRING_COL

    table_model: StringsTableModel

    def __init__(self, cfg, func=None, strings_model: StringsTableModel | None = None) -> None:
        super().__init__(strings_model if strings_model is not None else StringsTableModel(cfg, func))

    @property
    def cfg(self):
        return self.table_model.cfg

    @cfg.setter
    def cfg(self, v) -> None:
        self.table_model.cfg = v

    @property
    def xrefs(self):
        return self.table_model.xrefs

    @xrefs.setter
    def xrefs(self, v) -> None:
        self.table_model.xrefs = v

    @property
    def function(self):
        return self.table_model.function

    @function.setter
    def function(self, v) -> None:
        self.table_model.function = v

    @property
    def values(self) -> list[MemoryData]:
        """The strings shown, in their order."""
        return self.table_model.rows

    def __len__(self) -> int:
        return self.rowCount()


class QStringTable(QTableView):
    """The table of strings; X shows the cross-references to the selected one."""

    def __init__(
        self, instance: Instance, parent, selection_callback=None, strings_model: StringsTableModel | None = None
    ) -> None:
        super().__init__(parent)

        self._instance = instance
        self._selected = selection_callback
        self._filter = None

        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(24)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

        self._model = QStringModel(None, strings_model=strings_model)
        self.setModel(self._model)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        # let the last column (string) fill table width
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.horizontalHeader().setSectionResizeMode(QStringModel.STRING_COL, QHeaderView.ResizeMode.Stretch)

        self.doubleClicked.connect(self._on_string_selected)

    #
    # Properties
    #

    @property
    def cfg(self):
        return self._model.cfg

    @cfg.setter
    def cfg(self, v) -> None:
        self._model.cfg = v
        self.fast_resize()

    @property
    def xrefs(self):
        return self._model.xrefs

    @xrefs.setter
    def xrefs(self, v) -> None:
        self._model.xrefs = v

    @property
    def function(self):
        return self._model.function

    @function.setter
    def function(self, v) -> None:
        self._model.function = v
        self.fast_resize()

    @property
    def filter_string(self):
        return self._filter

    @filter_string.setter
    def filter_string(self, v) -> None:
        self._filter = v
        self._model.table_model.set_filter(v, regex=isinstance(v, re.Pattern))

    #
    # Public methods
    #

    def fast_resize(self) -> None:
        self.setVisible(False)
        self.resizeColumnsToContents()
        self.setVisible(True)

    def selected_string(self) -> MemoryData | None:
        selected_rows = list(self.selectionModel().selectedRows())
        if len(selected_rows) != 1:
            return None
        return self._model.table_model.row(selected_rows[0].row())

    #
    # Event handlers
    #

    def _on_string_selected(self, model_index) -> None:
        selected_item = self._model.table_model.row(model_index.row())
        if self._selected is not None:
            self._selected(selected_item)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_X:
            # xrefs
            selected_item = self.selected_string()
            if selected_item is not None:
                dialog = XRefDialog(
                    addr=selected_item.addr,
                    dst_addr=selected_item.addr,
                    xrefs_manager=self.xrefs,
                    instance=self._instance,
                    parent=self,
                )
                dialog.exec_()
            return

        super().keyPressEvent(event)
