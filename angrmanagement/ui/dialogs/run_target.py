from typing import Optional, TYPE_CHECKING

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QComboBox


ALL_TARGETS = {
    'symexec': "angr symbolic execution",
    'win_local': "Local debugging - Windows",
    'linux_local': "Local debugging - Linux",
    'macos_local': "Local debugging - macOS",
    'win_remote': "Remote debugging - Windows",
    'linux_remote': "Remote debugging - Linux",
    'macos_remote': "Remote debuggin - macOS",
}


class RunTargetDialog(QDialog):
    """
    Specify a target to run.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self._debugger_box: QComboBox = None
        self._ok_button: QPushButton = None
        self.main_layout: QVBoxLayout = QVBoxLayout()

        self._init_widgets()
        self.setWindowTitle("Run Target")

    #
    # Private methods
    #

    def _init_widgets(self):

        # debugger box

        debugger_box_lbl = QLabel("Target")

        debugger_box = QComboBox()
        # initialize the debugger box
        self._populate_targets(debugger_box)
        self._debugger_box = debugger_box

        debuger_layout = QHBoxLayout()
        debuger_layout.addWidget(debugger_box_lbl)
        debuger_layout.addWidget(debugger_box)
        self.main_layout.addLayout(debuger_layout)

        # options

        # OK button
        ok_button = QPushButton(self)
        ok_button.setText('OK')
        ok_button.setEnabled(False)
        ok_button.clicked.connect(self._on_ok_clicked)
        self._ok_button = ok_button

        # cancel button
        cancel_button = QPushButton(self)
        cancel_button.setText('Cancel')
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        self.main_layout.addLayout(buttons_layout)

        self.setLayout(self.main_layout)

    def _populate_targets(self, targets: QComboBox):
        """
        Populate the combo box for debuggees.
        """

        for v in ALL_TARGETS.values():
            targets.addItem(v)

    #
    # Event handlers
    #

    def _on_ok_clicked(self):
        self.close()

    def _on_cancel_clicked(self):
        self.close()
