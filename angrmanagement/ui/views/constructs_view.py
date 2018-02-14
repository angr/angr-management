
from PySide.QtGui import QHBoxLayout, QVBoxLayout, QLabel
from PySide.QtCore import QSize

from angr.knowledge_plugins import Function

from .view import BaseView
from ..widgets.qfunction_combobox import QFunctionComboBox
from ..widgets.qconstruct_table import QConstructTable


class ConstructsView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        super(ConstructsView, self).__init__('constructs', workspace, default_docking_position, *args, **kwargs)

        self.caption = 'Constructs'
        self._construct_table = None
        self._function_list = None

        self._selected_function = None

        self._init_widgets()

    def reload(self):
        self._function_list.functions = self.workspace.instance.cfg.functions
        self._construct_table.function = self._selected_function
        self._construct_table.loops = self.workspace.instance.loops

    def sizeHint(self):
        return QSize(200, 0)

    #
    # Event handlers
    #

    def _on_function_selected(self, function):

        if isinstance(function, (str, unicode)) and str(function) == "all":
            # all functions
            self._selected_function = None

        elif isinstance(function, Function):
            self._selected_function = function

        self.reload()

    def _init_widgets(self):

        # Function
        lbl_function = QLabel(self)
        lbl_function.setText("Function")
        self._function_list = QFunctionComboBox(show_all_functions=True, selection_callback=self._on_function_selected,
                                                parent=self
                                                )

        function_layout = QHBoxLayout()
        function_layout.addWidget(lbl_function)
        function_layout.addWidget(self._function_list)

        # Construct table

        self._construct_table = QConstructTable(self)

        vlayout = QVBoxLayout()
        vlayout.addLayout(function_layout)
        vlayout.addWidget(self._construct_table)
        vlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(vlayout)
