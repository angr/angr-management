from __future__ import annotations

from typing import TYPE_CHECKING

from pyqodeng.core.api import CodeEdit
from pyqodeng.core.modes import AutoIndentMode, CaretLineHighlighterMode, PygmentsSyntaxHighlighter
from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QLabel,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace


class HookDialog(QDialog):
    """
    Provide templetes of hook function.
    """

    def __init__(self, workspace: Workspace, addr: int | None = None, parent=None) -> None:
        super().__init__(parent)

        # initialization

        self.workspace = workspace
        self.state = None  # output
        self._addr = addr
        self.templates = {}
        self._add_templates(hex(addr))
        self._function_box = None
        self._ok_button = None
        self.setWindowTitle("Change hook")
        self.main_layout = QVBoxLayout()
        self._init_widgets()
        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _add_templates(self, addr: int) -> None:
        self.templates[
            "base"
        ] = f"""\
@project.hook(addr={addr}, length=0)
def hook(state):
    ..."""

        self.templates[
            "assertion"
        ] = f"""\
@project.hook(addr={addr}, length=0)
def assertion(state):
    state.add_constraints(
        ...
    )"""

        self.templates[
            "disable unicorn"
        ] = f"""\
@project.hook(addr={addr}, length=0)
def disable_unicorn(state):
    state.options.discard("UNICORN")
    state.options.discard("UNICORN_HANDLE_TRANSMIT_SYSCALL")
    state.options.discard("UNICORN_SYM_REGS_SUPPORT")
    state.options.discard("UNICORN_TRACK_BBL_ADDRS")
    state.options.discard("UNICORN_TRACK_STACK_POINTERS")
"""

        self.templates[
            "enable unicorn"
        ] = f"""\
@project.hook(addr={addr}, length=0)
def enable_unicorn(state):
    state.options.add("UNICORN")
    state.options.add("UNICORN_HANDLE_TRANSMIT_SYSCALL")
    state.options.add("UNICORN_SYM_REGS_SUPPORT")
    state.options.add("UNICORN_TRACK_BBL_ADDRS")
    state.options.add("UNICORN_TRACK_STACK_POINTERS")
"""

    def update_function(self, template) -> None:
        self._function_box.setPlainText(template, mime_type="text/x-python", encoding="utf-8")

    def selected(self) -> None:
        btn = self.sender()
        if btn.isChecked():
            self.update_function(btn.template)

    def _init_widgets(self) -> None:
        layout = QGridLayout()
        row = 0

        # validation_failures = set()
        addr = hex(self._addr)
        address_label = QLabel(self)
        address_label.setText(f"Hook at address {addr}:")

        layout.addWidget(address_label, row, 0)
        row += 1

        options_container = QGroupBox(self)
        options = QVBoxLayout()

        for name, template in sorted(self.templates.items()):
            child = QRadioButton()
            child.setText(name)
            child.template = template
            child.toggled.connect(self.selected)
            options.addWidget(child)

        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        widget = QWidget()
        scroll_area.setWidget(widget)
        layout_scroll = QVBoxLayout(widget)

        header_label = QLabel(self)
        header_label.setText("Presets:")

        layout_scroll.addWidget(header_label)
        layout_scroll.addWidget(options_container)
        options_container.setLayout(options)
        layout.addWidget(scroll_area, row, 0)
        row += 1

        function_box = CodeEdit(self)
        function_box.use_spaces_instead_of_tabs = True
        function_box.tab_length = 4

        function_box.modes.append(CaretLineHighlighterMode())
        function_box.modes.append(PygmentsSyntaxHighlighter(function_box.document()))
        function_box.modes.append(AutoIndentMode())

        function_box.setWordWrapMode(QTextOption.WrapMode.WordWrap)
        self._function_box = function_box

        layout.addWidget(function_box, row, 0)
        row += 1

        self.main_layout.addLayout(layout)

        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Append to Console")

        def do_ok() -> None:
            code = function_box.toPlainText()
            self.workspace.append_code_to_console(code)
            self.close()

        buttons.accepted.connect(do_ok)
        buttons.rejected.connect(self.close)
        self.main_layout.addWidget(buttons)
