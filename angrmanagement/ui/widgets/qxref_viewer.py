from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.present.xrefs import XRefMode, XRefsModel

from .qt_table import QtTableModelAdapter

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance

__all__ = ["QXRefAddressModel", "QXRefModel", "QXRefVariableModel", "QXRefViewer", "XRefMode"]


class QXRefModel(QtTableModelAdapter):
    """
    Qt model over a :class:`~angrmanagement.present.xrefs.XRefsModel`.

    It also takes the arguments it took before there was a neutral model, ``QXRefModel(addr, instance, view)``: it then
    shows the view's ``xrefs_model``, or a new model of the references to ``addr``.
    """

    HEADER: list[tuple[str, int]] = []

    table_model: XRefsModel

    def __init__(
        self, xrefs_model: XRefsModel | int | None = None, instance: Instance | None = None, view=None
    ) -> None:
        if not isinstance(xrefs_model, XRefsModel):
            addr = xrefs_model
            model = getattr(view, "xrefs_model", None)
            if not isinstance(model, XRefsModel):
                kb = instance.kb if instance is not None else None
                model = XRefsModel(
                    instance, addr=addr, xrefs_manager=kb.xrefs if kb is not None else None, dst_addr=addr
                )
            xrefs_model = model
        super().__init__(xrefs_model)
        self.addr = xrefs_model.addr
        self.instance = instance if instance is not None else xrefs_model.instance
        self.view = view

    @property
    def xrefs(self) -> list:
        return self.table_model.rows

    def __len__(self) -> int:
        return self.table_model.row_count


class QXRefVariableModel(QXRefModel):
    """The accesses of a variable."""

    HEADER = XRefsModel.VARIABLE_HEADER

    DIRECTION_COL = 0
    TYPE_COL = 1
    VARIABLE_COL = 2
    VARID_COL = 3
    PC_COL = 4
    TEXT_COL = 5


class QXRefAddressModel(QXRefModel):
    """The references to an address."""

    HEADER = XRefsModel.ADDRESS_HEADER

    DIRECTION_COL = 0
    TYPE_COL = 1
    PC_COL = 2
    TEXT_COL = 3


class QXRefViewer(QTableView):
    """The table of cross-references; double-clicking a row jumps to it through the dialog."""

    def __init__(
        self,
        addr: int | None = None,
        variable_manager=None,
        variable=None,
        xrefs_manager=None,
        dst_addr=None,
        instance: Instance | None = None,
        xref_dialog=None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setShowGrid(False)

        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self._instance = instance
        self._xref_dialog = xref_dialog
        self._addr = addr

        self.xrefs_model = XRefsModel(
            instance,
            addr=addr,
            variable_manager=variable_manager,
            variable=variable,
            xrefs_manager=xrefs_manager,
            dst_addr=dst_addr,
            on_jump=self._jump,
        )
        self.mode = self.xrefs_model.mode
        model_class = QXRefVariableModel if self.mode == XRefMode.Variable else QXRefAddressModel
        self._model = model_class(self.xrefs_model, instance, self)
        self.setModel(self._model)

        # set initial column widths
        for idx, (_, width) in enumerate(self._model.HEADER):
            self.setColumnWidth(idx, width)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        hheader = self.horizontalHeader()
        hheader.setStretchLastSection(True)
        hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)

        self.doubleClicked.connect(self._on_item_doubleclicked)

    @property
    def items(self) -> list:
        return self.xrefs_model.rows

    def _reload(self) -> None:
        self.xrefs_model.reload()

    #
    # Signal handlers
    #

    def _jump(self, addr: int) -> None:
        if self._xref_dialog is not None:
            self._xref_dialog.jump_to(addr)

    def _on_item_doubleclicked(self, model_index) -> None:
        self.xrefs_model.activate(model_index.row())
