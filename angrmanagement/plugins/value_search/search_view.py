from typing import TYPE_CHECKING

from PySide6.QtCore import QSize
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout

from angrmanagement.ui.views.view import BaseView

from .qsearch_table import QSearchTable

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData


class SearchView(BaseView):
    """
    Container view for the QSearchTable Object.
    Has handlers for switching between search types and executing the search.
    """

    def __init__(self, plugin, workspace, instance, default_docking_position, *args, **kwargs):
        super().__init__("search", workspace, instance, default_docking_position, *args, **kwargs)

        self.base_caption = "Search"
        self.plugin = plugin

        self._search_table: QSearchTable
        self._type_list: QComboBox

        self._selected_type = "bytes"

        self._init_widgets()
        self.reload()

    def reload(self):
        pass

    def sizeHint(self):
        return QSize(400, 800)

    #
    # Event handlers
    #

    def _on_search_click(self):
        self._selected_type = self._type_list.currentText()
        pattern = self._filter_string.text()
        self._value_table.filter_string = pattern
        self.reload()

    def _on_string_selected(self, s: "MemoryData"):
        """
        A string reference is selected.

        :param s:
        :return:
        """

        if len(self.workspace.view_manager.views_by_category["hex"]) == 1:
            hex_view = self.workspace.view_manager.first_view_in_category("hex")
        else:
            hex_view = self.workspace.view_manager.current_view_in_category("hex")
        if hex_view is not None:
            hex_view.jump_to(s[0])
            self.workspace.view_manager.raise_view(hex_view)

    #
    # Private methods
    #

    def _init_widgets(self):
        self._type_list = QComboBox(parent=self)
        self._type_list.addItems(["bytes", "int", "float"])
        self._search_button = QPushButton("Search", parent=self)
        self._filter_string = QLineEdit(self)
        self._search_button.clicked.connect(self._on_search_click)

        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Type:", self))
        search_layout.addWidget(self._type_list, 10)
        search_layout.addWidget(QLabel("Query:", self))
        search_layout.addWidget(self._filter_string, 10)
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
