from PySide2.QtWidgets import QHBoxLayout, QVBoxLayout, QLabel
from PySide2.QtCore import QSize

from angr.knowledge_plugins import Function
from angr.knowledge_plugins.cfg.memory_data import MemoryData

from .view import BaseView
from ..widgets.qstring_table import QStringTable
from ..widgets.qfunction_combobox import QFunctionComboBox


class StringsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(StringsView, self).__init__('strings', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Strings'

        self._string_table = None  # type: QStringTable
        self._function_list = None  # type: QFunctionComboBox

        self._selected_function = None

        self._init_widgets()

    def reload(self):
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

        disasm_view = self.workspace.view_manager.first_view_in_category('disassembly')
        disasm_view.jump_to(s.addr)
        disasm_view.select_label(s.addr)
        self.workspace.view_manager.raise_view(disasm_view)

    #
    # Private methods
    #

    def _init_widgets(self):
        lbl_function = QLabel(self)
        lbl_function.setText("Function")
        self._function_list = QFunctionComboBox(show_all_functions=True, selection_callback=self._on_function_selected,
                                                parent=self
                                                )

        function_layout = QHBoxLayout()
        function_layout.addWidget(lbl_function)
        function_layout.addWidget(self._function_list)

        self._string_table = QStringTable(self, selection_callback=self._on_string_selected)

        layout = QVBoxLayout()
        layout.addLayout(function_layout)
        layout.addWidget(self._string_table)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

