from __future__ import annotations

from typing import TYPE_CHECKING

from angr.knowledge_plugins import Function
from PySide6.QtCore import QSize
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout

from angrmanagement.present.strings import StringsPresenter
from angrmanagement.ui.widgets.qfunction_combobox import QFunctionComboBox
from angrmanagement.ui.widgets.qstring_table import QStringTable

from .view import InstanceView

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg.memory_data import MemoryData

    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class StringsView(InstanceView):
    """The strings the CFG found, all or those of one function, with a filter."""

    presenter: StringsPresenter

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__(
            "strings",
            workspace,
            default_docking_position,
            instance,
            StringsPresenter(workspace, instance, default_docking_position),
        )

        self.base_caption = "Strings"

        self._string_table: QStringTable
        self._function_list: QFunctionComboBox

        self._init_widgets()
        self.reload()

    def sizeHint(self):
        return QSize(400, 800)

    @property
    def _selected_function(self):
        return self.presenter.selected_function

    def reload(self) -> None:
        if self.instance.kb is None:
            return
        self._function_list.functions = self.instance.kb.functions
        self.presenter.reload()
        self._string_table.fast_resize()

    def select_function(self, function) -> None:
        self._function_list.select_function(function)

    #
    # Event handlers
    #

    def _on_function_selected(self, function) -> None:
        if isinstance(function, str) and function == "all":
            # all functions
            self.presenter.selected_function = None

        elif isinstance(function, Function):
            self.presenter.selected_function = function

        self.reload()

    def _on_string_selected(self, s: MemoryData) -> None:
        """
        A string reference is selected.

        :param s:
        :return:
        """

        self.presenter.select_string(s)

    def on_filter_change(self, **kwargs) -> None:  # pylint: disable=unused-argument
        self.presenter.set_filter(self._filter_string.text(), regex=self._regex_checkbox.isChecked())

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        self._function_list = QFunctionComboBox(
            show_all_functions=True, selection_callback=self._on_function_selected, parent=self
        )

        self._filter_string = QLineEdit(self)
        self._regex_checkbox = QCheckBox(".*", self)
        self._regex_checkbox.setToolTip("Regular expression")
        self._filter_string.textChanged.connect(self.on_filter_change)
        self._regex_checkbox.stateChanged.connect(self.on_filter_change)

        function_layout = QHBoxLayout()
        function_layout.addWidget(QLabel("Function:", self))
        function_layout.addWidget(self._function_list, 10)
        function_layout.addWidget(QLabel("Filter:", self))
        function_layout.addWidget(self._filter_string, 10)
        function_layout.addWidget(self._regex_checkbox)
        function_layout.setContentsMargins(3, 3, 3, 3)
        function_layout.setSpacing(3)

        self._string_table = QStringTable(
            self.instance, self, selection_callback=self._on_string_selected, strings_model=self.presenter.model
        )

        layout = QVBoxLayout()
        layout.addLayout(function_layout)
        layout.addWidget(self._string_table)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
