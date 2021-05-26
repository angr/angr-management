import os
import logging

from PySide2.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QFileDialog, QComboBox
from PySide2.QtCore import Qt

from ..menus.disasm_options_menu import DisasmOptionsMenu
from .qdisasm_graph import QDisassemblyGraph
from .qlinear_viewer import QLinearDisassembly

_l = logging.getLogger(__name__)


class QDisasmStatusBar(QFrame):
    def __init__(self, disasm_view, parent=None):
        super(QDisasmStatusBar, self).__init__(parent)

        self.disasm_view = disasm_view

        # widgets
        self._function_label: QLabel = None
        self._options_menu: DisasmOptionsMenu = None
        self._view_combo: QComboBox = None

        # information
        self._function = None

        self._init_menu()
        self._init_widgets()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, f):
        self._function = f

        self._update_function_address()

    @property
    def function_address(self):
        if self._function is None:
            return None
        return self._function.addr

    #
    # Initialization
    #

    def _init_widgets(self):

        # current function
        self._function_label = QLabel()

        self._view_combo = QComboBox(self)
        self._view_combo.addItem("Linear Disassembly", QLinearDisassembly)
        self._view_combo.addItem("Graph Disassembly", QDisassemblyGraph)
        self._view_combo.activated.connect(self._view_combo_changed)
        self.disasm_view.view_visibility_changed.connect(self._update_view_combo)

        # options button
        option_btn = QPushButton()
        option_btn.setText('Options')
        option_btn.setMenu(self._options_menu.qmenu())

        # Save image button
        saveimage_btn = QPushButton()
        saveimage_btn.setText('Save image...')
        saveimage_btn.clicked.connect(self._on_saveimage_btn_clicked)

        layout = QHBoxLayout()
        layout.setContentsMargins(2, 2, 2, 2)
        layout.addWidget(self._function_label)

        layout.addStretch(0)
        layout.addWidget(saveimage_btn)
        layout.addWidget(self._view_combo)
        layout.addWidget(option_btn)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _init_menu(self):
        self._options_menu = DisasmOptionsMenu(self.disasm_view)

    #
    # Private methods
    #

    def _view_combo_changed(self, index:int):
        {
            QLinearDisassembly: self.disasm_view.display_linear_viewer,
            QDisassemblyGraph: self.disasm_view.display_disasm_graph
        }[self._view_combo.itemData(index)]()

    def _update_view_combo(self):
        graph_type = type(self.disasm_view.current_graph)
        index = self._view_combo.findData(graph_type)
        self._view_combo.setCurrentIndex(index)

    def _update_function_address(self):
        if self.function_address is not None:
            self._function_label.setText("Function %x" % self.function_address)

    def _on_saveimage_btn_clicked(self):

        filename, folder = QFileDialog.getSaveFileName(self, 'Save image...',
                                           '',
                                           'PNG Files (*.png);;Bitmaps (*.bmp)'
                                           )
        if not filename or not folder:
            return

        self.disasm_view.save_image_to(os.path.join(folder, filename))
