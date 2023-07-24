from typing import TYPE_CHECKING, List, Optional

from PySide6 import QtWidgets

if TYPE_CHECKING:
    from angr.analyses.data_dep import BaseDepNode

    from angrmanagement.ui.widgets.qdatadepgraph_block import QDataDepGraphBlock


class QDataDepGraphSearch(QtWidgets.QDialog):
    """
    Dialog that allows the user to search for a DepNode based on its value, architecture name, or instruction address.
    """

    def __init__(self, parent: QtWidgets.QWidget, data_dep_graph):
        super().__init__(parent)
        self.setWindowTitle("Data Dependency Node Search")
        self._data_dep_graph = data_dep_graph
        self._curr_value_text = ""
        self._curr_addr_text = ""
        self._curr_name_text = ""
        self._rel_nodes: List[QDataDepGraphBlock] = []
        self._curr_search_idx = -1

        self._name_line_edit = QtWidgets.QLineEdit(self)
        self._value_line_edit = QtWidgets.QLineEdit(self)
        self._address_line_edit = QtWidgets.QLineEdit(self)

        self._search_btn = QtWidgets.QPushButton("Search")
        self._close_btn = QtWidgets.QPushButton("Close")
        self._error_lbl = QtWidgets.QLabel(self)

        self._layout_manager = QtWidgets.QVBoxLayout(self)
        self._init_widgets()

        # Connect to slots
        self._search_btn.clicked.connect(self._on_search_click)
        self._close_btn.clicked.connect(self._on_close_click)

    def _safe_node_retrieval(self) -> Optional["QDataDepGraphBlock"]:
        if self._rel_nodes and 0 <= self._curr_search_idx < len(self._rel_nodes):
            return self._rel_nodes[self._curr_search_idx]
        else:
            return None

    def _on_close_click(self):
        curr_search_node = self._safe_node_retrieval()
        if curr_search_node:
            curr_search_node.selected = False
        self.accept()

    def _on_search_click(self):
        """
        Iterate through matching nodes
        """

        def _node_predicate(node: "BaseDepNode"):
            nonlocal val_as_int
            nonlocal addr_as_int

            matches = True

            if val_as_int:
                matches &= node.value == val_as_int
            if addr_as_int:
                matches &= node.ins_addr == addr_as_int
            if self._curr_name_text:
                matches &= self._curr_name_text in str(node)
            return matches

        self._error_lbl.hide()

        if (
            self._curr_value_text != self._value_line_edit.text()
            or self._curr_addr_text != self._address_line_edit.text()
            or self._curr_name_text != self._name_line_edit.text()
        ):
            # Change in search criteria since last click, update matching nodes
            self._curr_addr_text = self._address_line_edit.text() if self._address_line_edit.text() else ""
            self._curr_value_text = self._value_line_edit.text() if self._value_line_edit.text() else ""
            self._curr_name_text = self._name_line_edit.text() if self._name_line_edit.text() else ""
            try:
                val_as_int = int(self._curr_value_text, 16) if self._curr_value_text else None
                addr_as_int = int(self._curr_addr_text, 16) if self._curr_addr_text else None
            except ValueError:
                self._error_lbl.setText("Input must be in hexadecimal format!")
                self._error_lbl.show()

            self._rel_nodes = [n for n in self._data_dep_graph.nodes if _node_predicate(n.node)]
        if len(self._rel_nodes) == 0:
            # No matching nodes, display an error
            self._error_lbl.setText("No nodes match the given search criteria.")
            self._error_lbl.show()
            return
        curr_search_node = self._safe_node_retrieval()
        if curr_search_node:
            # Deselect previous search node
            curr_search_node.selected = False

        self._curr_search_idx = (self._curr_search_idx + 1) % len(self._rel_nodes)
        search_node: QDataDepGraphBlock = self._rel_nodes[self._curr_search_idx]
        search_node.selected = True

        self._data_dep_graph.zoom(reset=True)
        self._data_dep_graph.centerOn(search_node)
        self._data_dep_graph.zoom(restore=True)
        self._data_dep_graph.refresh()

    def _init_widgets(self):
        self._error_lbl.hide()
        self._error_lbl.setStyleSheet(self._error_lbl.styleSheet() + "color: red;")

        form_layout = QtWidgets.QFormLayout()
        form_layout.addRow("Name", self._name_line_edit)
        form_layout.addRow("Value", self._value_line_edit)
        form_layout.addRow("Instruction address", self._address_line_edit)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch(0)
        btn_layout.addWidget(self._search_btn)
        btn_layout.addSpacing(10)
        btn_layout.addWidget(self._close_btn)
        btn_layout.addStretch(0)

        self._layout_manager.addLayout(form_layout)
        self._layout_manager.addSpacing(20)
        self._layout_manager.addLayout(btn_layout)
        self._layout_manager.addWidget(self._error_lbl)
