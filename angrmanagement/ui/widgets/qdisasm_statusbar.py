import os
from typing import TYPE_CHECKING, Optional

from PySide6.QtWidgets import QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QPushButton

from angrmanagement.ui.menus.disasm_options_menu import DisasmOptionsMenu
from angrmanagement.ui.toolbars import NavToolbar

from .qdisasm_base_control import DisassemblyLevel
from .qdisasm_graph import QDisassemblyGraph
from .qlinear_viewer import QLinearDisassembly

if TYPE_CHECKING:
    from angr.knowledge_plugins import Function


class QDisasmStatusBar(QFrame):
    """
    Status and control bar for disassembly views
    """

    def __init__(self, disasm_view, parent=None):
        super().__init__(parent)

        self.disasm_view = disasm_view

        # widgets
        self._nav_toolbar: Optional[NavToolbar] = None
        self._function_label: QLabel = None
        self._options_menu: DisasmOptionsMenu = None
        self._view_combo: QComboBox = None

        # information
        self._function: Optional[Function] = None

        self._init_menu()
        self._init_widgets()

    @property
    def function(self):
        return self._function

    @function.setter
    def function(self, f):
        self._function = f
        self._update_function_label()

    #
    # Initialization
    #

    def _init_widgets(self):
        self._nav_toolbar = NavToolbar(
            self.disasm_view.jump_history,
            self.disasm_view.jump_back,
            self.disasm_view.jump_forward,
            self.disasm_view.jump_to_history_position,
            True,
            self,
        )

        # current function
        self._function_label = QLabel()

        self._view_combo = QComboBox(self)
        self._view_combo.addItem("Linear Disassembly", QLinearDisassembly)
        self._view_combo.addItem("Graph Disassembly", QDisassemblyGraph)
        self._view_combo.activated.connect(self._view_combo_changed)
        self.disasm_view.view_visibility_changed.connect(self._update_view_combo)
        self._update_view_combo()

        self._disasm_level_combo = QComboBox(self)
        self._disasm_level_combo.addItem("Machine Code", DisassemblyLevel.MachineCode)
        self._disasm_level_combo.addItem("Lifter IR", DisassemblyLevel.LifterIR)
        self._disasm_level_combo.addItem("AIL", DisassemblyLevel.AIL)
        self._disasm_level_combo.activated.connect(self._disasm_level_combo_changed)
        self.disasm_view.disassembly_level_changed.connect(self._update_disasm_level_combo)
        self._update_disasm_level_combo()

        # options button
        option_btn = QPushButton()
        option_btn.setText("Options")
        option_btn.setMenu(self._options_menu.qmenu())

        # Save image button
        saveimage_btn = QPushButton()
        saveimage_btn.setText("Save image...")
        saveimage_btn.clicked.connect(self._on_saveimage_btn_clicked)

        layout = QHBoxLayout()
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        layout.addWidget(self._nav_toolbar.qtoolbar())
        layout.addWidget(self._function_label)

        layout.addStretch(0)

        layout.addWidget(saveimage_btn)
        layout.addWidget(self._view_combo)
        layout.addWidget(self._disasm_level_combo)
        layout.addWidget(option_btn)

        self.setLayout(layout)

    def _init_menu(self):
        self._options_menu = DisasmOptionsMenu(self.disasm_view)

    #
    # Private methods
    #

    def _view_combo_changed(self, index: int):
        {
            QLinearDisassembly: self.disasm_view.display_linear_viewer,
            QDisassemblyGraph: self.disasm_view.display_disasm_graph,
        }[self._view_combo.itemData(index)]()

    def _update_view_combo(self):
        graph_type = type(self.disasm_view.current_graph)
        index = self._view_combo.findData(graph_type)
        self._view_combo.setCurrentIndex(index)

    def _disasm_level_combo_changed(self, index: int):
        new_level = self._disasm_level_combo.itemData(index)
        self.disasm_view.set_disassembly_level(new_level)

    def _update_disasm_level_combo(self):
        new_level = self.disasm_view.disassembly_level
        index = self._disasm_level_combo.findData(new_level)
        self._disasm_level_combo.setCurrentIndex(index)

    def _update_function_label(self):
        s = f"{self._function.name} ({self._function.addr:x})" if self._function else ""
        self._function_label.setText(s)

    def _on_saveimage_btn_clicked(self):
        filename, folder = QFileDialog.getSaveFileName(self, "Save image...", "", "PNG Files (*.png);;Bitmaps (*.bmp)")
        if not filename or not folder:
            return

        self.disasm_view.save_image_to(os.path.join(folder, filename))
