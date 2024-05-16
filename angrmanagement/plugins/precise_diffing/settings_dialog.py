from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
)

from .function_diff import BFSFunctionDiff, LinearFunctionDiff


class SettingsDialog(QDialog):
    """
    A settings dialog for the Precise Diff plugin
    """

    def __init__(self, diff_plugin, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Precise Diff Settings")
        self.diff_plugin = diff_plugin

        self._main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self._main_layout)
        self.updates = False
        self.show()

    def _init_widgets(self) -> None:
        upper_layout = QVBoxLayout()

        #
        # Algorithm Choices
        #

        algo_group = QGroupBox(self)
        algo_group.setTitle("Precise Diffing Algorithm")
        algo_group_layout = QVBoxLayout()
        self._bfs_diff_btn = QRadioButton("Graph Breadth First Search")
        self._bfs_diff_btn.setToolTip(
            """
            Diffs two functions by traversing the graph in a BFS manner.
            Blocks that don't exist, or are out of order, in the new graph will be marked
            as ADDed instructions.
            """
        )
        self._linear_diff_btn = QRadioButton("Address Linear")
        self._linear_diff_btn.setToolTip(
            """
            Diffs two functions by linearly traversing the assembly of the original
            and checking for the same index in the new binary.
            """
        )
        self._use_addrs = QCheckBox("Use addresses for alignment")
        self._use_addrs.setToolTip(
            """
            When enabled, the diffing algorithm will attempt to diff functions at the same addresses across
            both binaries. When disabled we attempt to use symbols.
            """
        )
        self._use_addrs.setChecked(self.diff_plugin.use_addrs)

        if self.diff_plugin.diff_algo_class == BFSFunctionDiff:
            self._bfs_diff_btn.setChecked(True)
            self._linear_diff_btn.setChecked(False)
        elif self.diff_plugin.diff_algo_class == LinearFunctionDiff:
            self._bfs_diff_btn.setChecked(False)
            self._linear_diff_btn.setChecked(True)

        algo_group_layout.addWidget(self._bfs_diff_btn)
        algo_group_layout.addWidget(self._linear_diff_btn)
        algo_group_layout.addWidget(self._use_addrs)
        algo_group.setLayout(algo_group_layout)

        upper_layout.addWidget(algo_group)

        #
        # Instruction
        #

        ins_group = QGroupBox(self)
        ins_group.setTitle("Instruction Diffing Options")
        ins_layout = QVBoxLayout()
        self._prefer_symbols = QCheckBox("Prioritize Symbols", self)
        self._prefer_symbols.setToolTip(
            """
            Some instructions that use symbols, such as moves from global vars, may show different addresses
            in the new binary. With this option enabled, two instructions are marked as the same if at least
            the symbol name lines up.
            """
        )
        self._prefer_symbols.setChecked(self.diff_plugin.prefer_symbols)
        self._prefer_strings = QCheckBox("Prioritize Strings", self)
        self._prefer_strings.setToolTip(
            """
            Some instructions that use strings, such as moves from memory, may show different addresses
            in the new binary. With this option enabled, two instructions that move an address that point to the
            same string are marked as the same.
            """
        )
        self._prefer_strings.setChecked(self.diff_plugin.resolve_strings)
        self._prefer_insns = QCheckBox("Prioritize Instructions", self)
        self._prefer_insns.setToolTip(
            """
            Some instructions that use addresses, such as jumps, may show different addresses
            in the new binary. With this option enabled, two instructions that use an address that both point
            to the same first few instructions are marked as the same.
            """
        )
        self._prefer_insns.setChecked(self.diff_plugin.resolve_insns)
        self._ignore_globals = QCheckBox("Ignore Unnamed Globals")
        self._ignore_globals.setToolTip(
            """
            When enabled, ignores all unnamed global values when showing psuedocode diffs.
            """
        )
        self._ignore_globals.setChecked(self.diff_plugin.ignore_globals)

        ins_layout.addWidget(self._prefer_symbols)
        ins_layout.addWidget(self._prefer_strings)
        ins_layout.addWidget(self._prefer_insns)
        ins_layout.addWidget(self._ignore_globals)
        ins_group.setLayout(ins_layout)

        upper_layout.addWidget(ins_group)

        #
        # GUI Settings
        #

        gui_group = QGroupBox(self)
        gui_group.setTitle("GUI Options")
        gui_layout = QGridLayout()

        change_label = QLabel("Diff Change Color", self)
        change_label.setToolTip("The color shown when two instructions differ in some sub-change (like ops)")
        change_label.setStyleSheet(f"background-color: #{self.diff_plugin.chg_color.rgba() & 0xffffff:x}")
        self._change_color = QLineEdit()
        self._change_color.setText(hex(self.diff_plugin.chg_color.rgb()))
        gui_layout.addWidget(change_label, 0, 0)
        gui_layout.addWidget(self._change_color, 0, 1)

        add_label = QLabel("Diff Add Color", self)
        add_label.setToolTip("The color shown when an instruction can't be matched so it's assumed to be new")
        add_label.setStyleSheet(f"background-color: #{self.diff_plugin.add_color.rgba() & 0xffffff:x}")
        self._add_color = QLineEdit()
        self._add_color.setText(hex(self.diff_plugin.add_color.rgb()))
        gui_layout.addWidget(add_label, 1, 0)
        gui_layout.addWidget(self._add_color, 1, 1)

        del_label = QLabel("Diff Delete Color", self)
        del_label.setToolTip(
            "The color shown in the original binary where an instruction was removed (disabled for now)"
        )
        del_label.setStyleSheet(f"background-color: #{self.diff_plugin.del_color.rgba() & 0xffffff:x}")
        self._del_color = QLineEdit()
        self._del_color.setText(hex(self.diff_plugin.del_color.rgb()))
        gui_layout.addWidget(del_label, 2, 0)
        gui_layout.addWidget(self._del_color, 2, 1)
        gui_group.setLayout(gui_layout)

        upper_layout.addWidget(gui_group)

        #
        # Ok and Cancel Buttons
        #

        self._ok_button = QPushButton(self)
        self._ok_button.setText("OK")
        self._ok_button.setDefault(True)
        self._ok_button.clicked.connect(self._on_ok_clicked)

        cancel_button = QPushButton(self)
        cancel_button.setText("Cancel")
        cancel_button.clicked.connect(self._on_cancel_clicked)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self._ok_button)
        buttons_layout.addWidget(cancel_button)

        # main layout
        self._main_layout.addLayout(upper_layout)
        self._main_layout.addLayout(buttons_layout)

    def _on_ok_clicked(self) -> None:
        # algorithms
        if self._bfs_diff_btn.isChecked():
            self.diff_plugin.diff_algo_class = BFSFunctionDiff
        else:
            self.diff_plugin.diff_algo_class = LinearFunctionDiff
        self.diff_plugin.use_addrs = self._use_addrs.isChecked()

        # instruction options
        self.diff_plugin.prefer_symbols = self._prefer_symbols.isChecked()
        self.diff_plugin.resolve_strings = self._prefer_strings.isChecked()
        self.diff_plugin.resolve_insns = self._prefer_insns.isChecked()

        # colors
        try:
            self.diff_plugin.add_color = QColor(int(self._add_color.text(), 16))
            self.diff_plugin.chg_color = QColor(int(self._change_color.text(), 16))
            self.diff_plugin.del_color = QColor(int(self._del_color.text(), 16))
        except ValueError:
            pass

        self.updates = True
        self.close()

    def _on_cancel_clicked(self) -> None:
        self.close()
