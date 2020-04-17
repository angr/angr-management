from PySide2.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QHeaderView
from PySide2.QtCore import Qt


class XRefMode:
    Variable = 'variable'
    Address = 'address'


class AddressTableWidgetItem(QTableWidgetItem):
    def __init__(self, address):
        super(AddressTableWidgetItem, self).__init__("%x" % address)

        self.address = address

    def __le__(self, other):
        return self.address <= other.address


class QXRefViewerVariableItem:
    def __init__(self, addr, variable_access, instance):
        self._addr = addr
        self._variable_access = variable_access
        self._instance = instance

    def widgets(self):

        if self._variable_access.location.ins_addr < self._addr:
            direction = "up"
        elif self._variable_access.location.ins_addr > self._addr:
            direction = "down"
        else:
            direction = ""

        access_type_str = self._variable_access.access_type
        ident_str = self._variable_access.variable.ident
        text = self._instance.get_instruction_text_at(self._variable_access.location.ins_addr)
        if text is None:
            text = "-=unavailable=-"

        widgets = [
            QTableWidgetItem(direction),
            QTableWidgetItem(access_type_str),
            QTableWidgetItem(ident_str),
            QTableWidgetItem(AddressTableWidgetItem(self._variable_access.location.ins_addr)),
            QTableWidgetItem(text),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QXRefViewerAddressItem:
    def __init__(self, addr, xref, instance):
        self._addr = addr
        self._xref = xref
        self._instance = instance

    def widgets(self):

        if self._xref.ins_addr < self._addr:
            direction = "up"
        elif self._xref.ins_addr > self._addr:
            direction = "down"
        else:
            direction = ""
        access_type_str = self._xref.type_string

        widgets = [
            QTableWidgetItem(direction),
            QTableWidgetItem(access_type_str),
            QTableWidgetItem(AddressTableWidgetItem(self._xref.ins_addr)),
            QTableWidgetItem("TODO"),
        ]

        for w in widgets:
            w.setFlags(w.flags() & ~Qt.ItemIsEditable)

        return widgets


class QXRefViewer(QTableWidget):

    VARIABLE_HEADER = [('Direction', 70), ('Type', 50), ('Var. Ident.', 100), ('PC', 80), ('Text', 300)]
    ADDRESS_HEADER = [('Direction', 70), ('Type', 50), ('PC', 80), ('Text', 300)]

    def __init__(self, addr=None, variable_manager=None, variable=None, xrefs_manager=None, dst_addr=None,
                 instance=None, parent=None):
        super(QXRefViewer, self).__init__(parent)

        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setHorizontalScrollMode(self.ScrollPerPixel)
        self.setShowGrid(False)

        self.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
        self.verticalHeader().setDefaultSectionSize(24)

        self._instance = instance
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
            header = QXRefViewer.VARIABLE_HEADER
        elif self._xrefs_manager is not None and self._dst_addr is not None:
            self.mode = XRefMode.Address
            header = QXRefViewer.ADDRESS_HEADER
        else:
            raise ValueError("Unsupported mode. Either variable or dst_addr should be specified.")

        self.setColumnCount(len(header))
        self.setHorizontalHeaderLabels([ h[0] for h in header ])
        for i, (_, width) in enumerate(header):
            self.setColumnWidth(i, width)

        self.setSortingEnabled(True)
        self.setSelectionMode(QAbstractItemView.SingleSelection)

        self.items = [ ]

        self._reload()

    def _reload(self):
        if self.mode == XRefMode.Variable:
            accesses = self._variable_manager.get_variable_accesses(self._variable, same_name=True)
            self.items = [ QXRefViewerVariableItem(self._addr, acc, self._instance) for acc in accesses ]
        else:  # self.mode == XRefMode.Address
            xrefs = self._xrefs_manager.get_xrefs_by_dst(self._dst_addr)
            self.items = [ QXRefViewerAddressItem(self._addr, xref, self._instance) for xref in xrefs ]

        items_count = len(self.items)
        self.setRowCount(items_count)

        for idx, item in enumerate(self.items):
            for i, it in enumerate(item.widgets()):
                self.setItem(idx, i, it)
