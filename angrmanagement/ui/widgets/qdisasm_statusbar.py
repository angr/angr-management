import os
import logging

from PySide2.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QFileDialog
from PySide2.QtCore import Qt

from ..menus.disasm_options_menu import DisasmOptionsMenu

_l = logging.getLogger(__name__)

class QDisasmStatusBar(QFrame):
    def __init__(self, disasm_view, parent=None):
        super(QDisasmStatusBar, self).__init__(parent)

        self.disasm_view = disasm_view

        # widgets
        self._saveimage_btn = None  # type: QPushButton
        self._function_label = None  # type: QLabel
        self._options_menu = None  # type: DisasmOptionsMenu

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
        function_label = QLabel()
        self._function_label = function_label

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
        layout.addWidget(function_label)

        layout.addStretch(0)
        layout.addWidget(saveimage_btn)
        layout.addWidget(option_btn)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _init_menu(self):
        self._options_menu = DisasmOptionsMenu(self.disasm_view)

    #
    # Private methods
    #

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
