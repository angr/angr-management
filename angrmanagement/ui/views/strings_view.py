import re
from PySide2.QtWidgets import QCheckBox, QHBoxLayout, QLineEdit, QVBoxLayout, QLabel
from PySide2.QtCore import QSize

from angr.knowledge_plugins import Function
from angr.knowledge_plugins.cfg.memory_data import MemoryData

from .view import BaseView
from ..widgets.qstring_table import QStringTable
from ..widgets.qfunction_combobox import QFunctionComboBox


class StringsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(StringsView, self).__init__('strings', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = 'Strings'

        self._string_table = None  # type: QStringTable
        self._function_list = None  # type: QFunctionComboBox

        self._selected_function = None

        self._init_widgets()
        self.reload()

    def reload(self):
        if self.workspace.instance.kb is None:
            return
        self._function_list.functions = self.workspace.instance.kb.functions
        self._string_table.cfg = self.workspace.instance.cfg
        self._string_table.xrefs = self.workspace.instance.project.kb.xrefs
        self._string_table.function = self._selected_function

    def sizeHint(self):
        return QSize(400, 800)

    #
    # Event handlers
    #

    def _on_function_selected(self, function):

        if isinstance(function, str) and function == "all":
            # all functions
            self._selected_function = None

        elif isinstance(function, Function):
            self._selected_function = function

        self.reload()

    def _on_string_selected(self, s: MemoryData):
        """
        A string reference is selected.

        :param s:
        :return:
        """

        if len(self.workspace.view_manager.views_by_category['disassembly']) == 1:
            disasm_view = self.workspace.view_manager.first_view_in_category('disassembly')
        else:
            disasm_view = self.workspace.view_manager.current_view_in_category('disassembly')
        if disasm_view is not None:
            disasm_view.jump_to(s.addr)
            disasm_view.select_label(s.addr)
            self.workspace.view_manager.raise_view(disasm_view)

    def on_filter_change(self, **kwargs): #pylint: disable=unused-argument
        pattern = self._filter_string.text()
        regex = self._regex_checkbox.isChecked()
        if regex:
            try:
                pattern = re.compile(pattern)
            except re.error as _e:
                return
        self._string_table.filter_string = pattern

    #
    # Private methods
    #

    def _init_widgets(self):

        self._function_list = QFunctionComboBox(show_all_functions=True, selection_callback=self._on_function_selected,
                                                parent=self
                                                )

        self._filter_string = QLineEdit(self)
        self._regex_checkbox = QCheckBox("Regex?", self)
        self._filter_string.textChanged.connect(self.on_filter_change)
        self._regex_checkbox.stateChanged.connect(self.on_filter_change)

        function_layout = QHBoxLayout()
        function_layout.addWidget(QLabel("Function:",self))
        function_layout.addWidget(self._function_list, 10)
        function_layout.addWidget(QLabel("Filter:",self))
        function_layout.addWidget(self._filter_string, 10)
        function_layout.addWidget(self._regex_checkbox)

        self._string_table = QStringTable(self, selection_callback=self._on_string_selected)

        layout = QVBoxLayout()
        layout.addLayout(function_layout)
        layout.addWidget(self._string_table)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
