from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from angrmanagement.ui.views.view import InstanceView

from .constants import CONSTANTS_BY_NAME
from .qsearch_table import QSearchTable

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class SearchView(InstanceView):
    """
    Container view for the QSearchTable Object.
    Has handlers for switching between search types and executing the search.
    """

    def __init__(
        self, plugin, workspace: Workspace, default_docking_position: str, instance: Instance, *args, **kwargs
    ) -> None:
        super().__init__("search", workspace, default_docking_position, instance, *args, **kwargs)

        self.base_caption = "Search"
        self.plugin = plugin

        self._search_table: QSearchTable
        self._type_list: QComboBox
        self._alignment_input: QSpinBox

        self._selected_type = "bytes"
        self.should_search_code = False

        self._init_widgets()
        self.reload()

    def reload(self) -> None:
        pass

    def sizeHint(self):
        return QSize(400, 800)

    @property
    def alignment(self) -> int:
        return self._alignment_input.value()

    #
    # Event handlers
    #

    def _on_search_click(self) -> None:
        self._selected_type = self._type_list.currentText()
        pattern = self._filter_string.text()
        self._value_table.filter_string = pattern
        self.reload()

    def _on_string_selected(self, s: MemoryData) -> None:
        """
        A string reference is selected.

        :param s:
        :return:
        """
        view_name = "disassembly" if self.should_search_code else "hex"
        if len(self.workspace.view_manager.views_by_category[view_name]) == 1:
            hex_view = self.workspace.view_manager.first_view_in_category(view_name)
        else:
            hex_view = self.workspace.view_manager.current_view_in_category(view_name)
        if hex_view is not None:
            hex_view.jump_to(s.addr)
            self.workspace.view_manager.raise_view(hex_view)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._search_code_box = QCheckBox("Search code", parent=self)
        self._search_code_box.setChecked(False)
        self._search_code_box.stateChanged.connect(self._on_search_code_changed)
        self._type_list = QComboBox(parent=self)
        self._type_list.addItems(["bytes", "char", "int", "float", "double"])
        self._search_button = QPushButton("Search", parent=self)
        self._filter_string = QLineEdit(self)
        self._search_button.clicked.connect(self._on_search_click)
        self._alignment_input = QSpinBox(self)
        self._alignment_input.setValue(1)
        self._alignment_input.setRange(1, 256)

        constants_btn = QPushButton(self)
        constants_btn.setText("Constants")
        constants_mnu = QMenu(self)
        constants_btn.setMenu(constants_mnu)
        for n, v in CONSTANTS_BY_NAME.items():
            act = QAction(f"{n}: {v}", constants_mnu)
            act.setData(str(v))
            act.triggered.connect(self._on_constant_selected)
            constants_mnu.addAction(act)

        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Query:", self))
        search_layout.addWidget(self._filter_string, 1)
        search_layout.addWidget(constants_btn)
        search_layout.addWidget(QLabel("Type:", self))
        search_layout.addWidget(self._type_list)
        search_layout.addWidget(QLabel("Alignment (bytes):", self))
        search_layout.addWidget(self._alignment_input)
        search_layout.addWidget(self._search_code_box)
        search_layout.addWidget(self._search_button)
        search_layout.setContentsMargins(3, 3, 3, 3)
        search_layout.setSpacing(3)

        self._value_table = QSearchTable(self.instance, self, selection_callback=self._on_string_selected)

        layout = QVBoxLayout()
        layout.addLayout(search_layout)
        layout.addWidget(self._value_table)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _on_search_code_changed(self, state) -> None:
        self.should_search_code = state == 2

    def _on_constant_selected(self) -> None:
        self._filter_string.setText(self.sender().data())
