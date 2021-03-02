from ..base_plugin import BasePlugin

from PySide2.QtCore import Qt
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QInputDialog, QMessageBox, QVBoxLayout, QPushButton
from angrmanagement.ui.views import BaseView
from angrmanagement.ui.widgets.qfunction_combobox import QFunctionComboBox
from angrmanagement.ui.widgets.qfunction_table import QFunctionTableView, QFunctionTableModel, QFunctionTable

class ReFuzzView(BaseView):
    def __init__(self, workspace, default_docking_position, *args, **kwargs):
        if 'plugin' not in kwargs:
            return
        else:
            self.plugin = kwargs['plugin']
            del kwargs['plugin']

        super().__init__('refuzz', workspace, default_docking_position, *args, **kwargs)

        self.caption = "ReFuzz"
        self.category = "Patching"

        self._init_widgets()

    def _init_widgets(self):
        layout = QVBoxLayout()
        self.get_suggestions_button = QPushButton("Get Patch Suggestions")
        self.get_suggestions_button.clicked.connect(self.plugin.get_patch_suggestions)
        self.patch_function_button = QPushButton("Patch Selected Function")
        self.patch_function_button.clicked.connect(self.plugin.patch_function)
        self.patch_function_selector = QFunctionTable(self, workspace=self.plugin.workspace, selection_callback=self.plugin.set_selected_function)
        #self.patch_function_selector_view = QFunctionTableView(parent=self.patch_function_selector, workspace=self.plugin.workspace, selection_callback=self.plugin.set_selected_function)
        layout.addWidget(self.get_suggestions_button)
        layout.addWidget(self.patch_function_button)
        layout.addWidget(self.patch_function_selector)
        self.setLayout(layout)

class RefuzzPlugin(BasePlugin):
    REQUIRE_WORKSPACE = True
    MENU_BUTTONS = ('Get Patch Suggestions', 'Patch Function')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace.instance.register_container('refuzz', lambda: None, None, 'Refuzz Control Panel')
        self.view = ReFuzzView(plugin=self, workspace=self.workspace, default_docking_position='center')
        self.workspace.add_view(self.view, self.view.caption, self.view.category)
        self.handlers = {
            0: self.get_patch_suggestions,
            1: self.patch_function
        }

    def handle_click_menu(self, idx):
        if idx < 0 or idx > len(self.buttons):
            return

        if self.workspace.instance.project is None:
            return

        self.handlers[idx]()

    def get_patch_suggestions(self):
        pass


    def patch_function(self):
        pass

    def set_selected_function(self):
        pass