from typing import TYPE_CHECKING, List

from angr.knowledge_plugins.variables.variable_access import VariableAccess
from angr.knowledge_plugins.xrefs.xref import XRef, XRefType
from PySide6.QtCore import QAbstractTableModel, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from angrmanagement.config import Conf

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance


class XRefMode:
    Variable = "variable"
    Address = "address"


class QXRefModel(QAbstractTableModel):
    HEADER = []

    def __init__(self, addr, instance, view):
        super().__init__()

        self.addr = addr
        self.instance = instance
        self.view = view

    @property
    def xrefs(self) -> List[VariableAccess]:
        return self.view.items

    @xrefs.setter
    def xrefs(self, v):
        self.view.items = v

    def __len__(self):
        return len(self.xrefs)

    def rowCount(self, parent=None):
        return len(self.xrefs)

    def columnCount(self, parent=None):
        return len(self.HEADER)

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole:
            if section < len(self.HEADER):
                return self.HEADER[section][0]
        elif role == Qt.InitialSortOrderRole:
            return Qt.AscendingOrder

        return None

    def data(self, index, role):
        if not index.isValid():
            return None

        row = index.row()
        if row >= len(self.xrefs):
            return None

        col = index.column()
        xref = self.xrefs[row]

        if role == Qt.DisplayRole:
            return self._get_column_text(xref, col)

        elif role == Qt.FontRole:
            return Conf.tabular_view_font

        return None

    def sort(self, column, order):
        self.layoutAboutToBeChanged.emit()

        self.xrefs = sorted(
            self.xrefs,
            key=lambda x: self._get_column_data(x, column),
            reverse=order == Qt.DescendingOrder,
        )
        self.layoutChanged.emit()

    def _get_column_text(self, xref, idx):
        if idx < len(self.HEADER):
            data = self._get_column_data(xref, idx)
            if type(data) is int:
                return hex(data)
            return data

    #
    # Abstract methods
    #

    def _get_column_data(self, xref, idx):
        raise NotImplementedError()


class QXRefVariableModel(QXRefModel):
    HEADER = [("Direction", 70), ("Type", 50), ("Variable", 80), ("VarId", 80), ("PC", 160), ("Text", 300)]

    DIRECTION_COL = 0
    TYPE_COL = 1
    VARIABLE_COL = 2
    VARID_COL = 3
    PC_COL = 4
    TEXT_COL = 5

    def _get_column_data(self, ref, idx):
        """

        :param VariableAccess ref:
        :param idx:
        :return:
        """
        mapping = {
            self.DIRECTION_COL: self._direction,
            self.TYPE_COL: self._access_type,
            self.VARIABLE_COL: self._varname,
            self.VARID_COL: self._identstr,
            self.PC_COL: self._addrstr,
            self.TEXT_COL: self._text,
        }

        handler = mapping.get(idx, None)
        if handler is not None:
            return handler(ref)
        return None

    def _addrstr(self, _r):
        addr = _r.location.ins_addr
        node = self.instance.cfg.get_any_node(addr, anyaddr=True)
        if node is not None and node.function_address is not None:
            return f"{addr:#x} ({self.instance.kb.functions[node.function_address].name})"
        return hex(addr)

    def _direction(self, _r):
        """

        :param VariableAccess _r:
        :return:
        """
        if _r.location.ins_addr < self.addr:
            return "up"
        elif _r.location.ins_addr > self.addr:
            return "down"
        return ""

    @staticmethod
    def _access_type(_r):
        """

        :param VariableAccess _r:
        :return:
        """
        return _r.access_type

    @staticmethod
    def _varname(_r):
        """

        :param VariableAccess _r:
        :return:
        """
        return _r.variable.name

    @staticmethod
    def _identstr(_r):
        """

        :param VariableAccess _r:
        :return:
        """
        return _r.variable.ident

    def _text(self, _r):
        """

        :param VariableAccess _r:
        :return:
        """
        text = self.instance.get_instruction_text_at(_r.location.ins_addr)
        if text is None:
            text = "-=unavailable=-"
        return text


class QXRefAddressModel(QXRefModel):
    HEADER = [("Direction", 70), ("Type", 50), ("PC", 160), ("Text", 300)]

    DIRECTION_COL = 0
    TYPE_COL = 1
    PC_COL = 2
    TEXT_COL = 3

    def _get_column_data(self, ref, idx):
        """

        :param XRef ref:
        :param int idx:
        :return:
        """
        mapping = {
            self.DIRECTION_COL: self._direction,
            self.TYPE_COL: self._access_type,
            self.PC_COL: self._addrstr,
            self.TEXT_COL: self._text,
        }

        handler = mapping.get(idx, None)
        if handler is not None:
            return handler(ref)
        return None

    def _addrstr(self, _r):
        addr = _r.ins_addr
        node = self.instance.cfg.get_any_node(addr, anyaddr=True)
        if node is not None and node.function_address is not None:
            return f"{addr:#x} ({self.instance.kb.functions[node.function_address].name})"
        return hex(addr)

    def _direction(self, _r):
        """

        :param XRef _r:
        :return:
        """
        if _r.ins_addr < self.addr:
            return "up"
        elif _r.ins_addr > self.addr:
            return "down"
        return ""

    @staticmethod
    def _access_type(_r):
        """

        :param XRef _r:
        :return:
        """
        return _r.type_string

    def _text(self, _r):
        """

        :param XRef _r:
        :return:
        """
        text = self.instance.get_instruction_text_at(_r.ins_addr)
        if text is None:
            text = "-=unavailable=-"
        return text


class QXRefViewer(QTableView):
    def __init__(
        self,
        addr=None,
        variable_manager=None,
        variable=None,
        xrefs_manager=None,
        dst_addr=None,
        instance: "Instance" = None,
        xref_dialog=None,
        parent=None,
    ):
        super().__init__(parent)

        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setShowGrid(False)

        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self._instance = instance
        self._xref_dialog = xref_dialog
        self._addr = addr

        # Two modes
        # Mode A: (local-)variable-based
        self._variable_manager = variable_manager
        self._variable = variable
        # Mode B: Global address based
        self._xrefs_manager = xrefs_manager
        self._dst_addr = dst_addr

        # Determine which mode we are at
        if self._variable_manager is not None and self._variable is not None:
            self.mode = XRefMode.Variable
        elif self._xrefs_manager is not None and self._dst_addr is not None:
            self.mode = XRefMode.Address
        else:
            raise ValueError("Unsupported mode. Either variable or dst_addr should be specified.")

        self.items = []
        self._reload()

        if self.mode == XRefMode.Variable:
            self._model = QXRefVariableModel(self._addr, self._instance, self)
        elif self.mode == XRefMode.Address:
            self._model = QXRefAddressModel(self._addr, self._instance, self)
        else:
            raise ValueError("Unsupported mode. Either variable or dst_addr should be specified.")
        self.setModel(self._model)

        # set initial column widths
        for idx, (_, width) in enumerate(self._model.HEADER):
            self.setColumnWidth(idx, width)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        hheader = self.horizontalHeader()
        hheader.setStretchLastSection(True)
        hheader.setSectionResizeMode(0, QHeaderView.ResizeToContents)

        self.doubleClicked.connect(self._on_item_doubleclicked)

    def _reload(self):
        if self.mode == XRefMode.Variable:
            self.items = self._variable_manager.get_variable_accesses(self._variable, same_name=True)
            self.items = sorted(self.items, key=lambda item: item.location.ins_addr)
        else:  # self.mode == XRefMode.Address
            self.items = list(self._xrefs_manager.get_xrefs_by_dst(self._dst_addr))

            # Create XRef objects for addresses inside the CFG
            self.items += list(self._xrefs_from_control_flow_transitions())
            self.items = sorted(self.items, key=lambda item: item.ins_addr)

    def _xrefs_from_control_flow_transitions(self):
        if self._instance is not None:
            cfg = self._instance.cfg
            node = cfg.get_any_node(self._dst_addr)
            if node is not None:
                # its predecessors
                predecessors = cfg.get_predecessors(node)
                arch = self._instance.project.arch
                for pred in predecessors:
                    if pred.instruction_addrs:
                        if arch.branch_delay_slot and len(pred.instruction_addrs) > 1:
                            ins_addr = pred.instruction_addrs[-2]
                        else:
                            ins_addr = pred.instruction_addrs[-1]
                    else:
                        ins_addr = pred.addr
                    yield XRef(
                        ins_addr=ins_addr,
                        block_addr=pred.addr,
                        stmt_idx=None,
                        dst=self._dst_addr,
                        xref_type=XRefType.Offset,
                    )

    #
    # Signal handlers
    #

    def _on_item_doubleclicked(self, model_index):
        row = model_index.row()
        xref_dialog = self._xref_dialog
        if xref_dialog is None:
            return

        item = self.items[row]
        if isinstance(item, VariableAccess):
            xref_dialog.jump_to(item.location.ins_addr)
        elif isinstance(item, XRef):
            xref_dialog.jump_to(item.ins_addr)
