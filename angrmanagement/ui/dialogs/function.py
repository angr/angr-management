from __future__ import annotations

from pygments.lexers.c_cpp import CLexer
from pyqodeng.core.api import CodeEdit
from pyqodeng.core.modes import PygmentsSyntaxHighlighter
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
)

from angrmanagement.config import Conf
from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.widgets.qccode_edit import ColorSchemeIDA
from angrmanagement.utils.layout import add_to_grid


class FunctionDialog(QDialog):
    """
    Dialog displaying information about a Function.
    """

    def __init__(self, function, parent=None) -> None:
        super().__init__(parent)
        self.workspace = GlobalInfo.main_window.workspace
        self.function = function
        self._init_widgets()
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setWindowTitle(f"Function {self.function.name}")
        self.setMinimumWidth(600)
        self.adjustSize()

    def _init_widgets(self) -> None:
        font = QFont(Conf.disasm_font)

        main_layout = QGridLayout()
        self.setLayout(main_layout)

        r = 0

        for label, text in [
            ("Name:", self.function.name),
            ("Address:", f"{self.function.addr:x}"),
            ("Binary:", f"{self.function.binary}"),
            ("Offset:", f"{self.function.offset:x}"),
            (
                "Calling Convention:",
                "<Unknown>" if self.function.calling_convention is None else f"{self.function.calling_convention}",
            ),
            ("Tags:", ", ".join(self.function.tags)),
            ("Cyclomatic Complexity:", str(self.function.cyclomatic_complexity)),
        ]:
            main_layout.addWidget(QLabel(label), r, 0)
            le = QLineEdit(text, self)
            le.setFont(font)
            le.setReadOnly(True)  # FIXME: Support editing
            main_layout.addWidget(le, r, 1)
            r += 1

        main_layout.addWidget(QLabel("C Prototype:"), r, 0)
        ce = CodeEdit(self)
        if self.function.prototype is not None:
            decl = self.function.prototype.c_repr(full=True).replace("()", self.function.name, 1) + ";"
            ce.document().setPlainText(decl)
        ce.modes.append(PygmentsSyntaxHighlighter(ce.document(), CLexer(), ColorSchemeIDA()))
        ce.setFixedHeight(ce.fontMetrics().height() * 2)
        ce.setReadOnly(True)  # FIXME: Support editing
        main_layout.addWidget(ce, r, 1)
        r += 1

        attrs_group_box = QGroupBox("Attributes")
        attrs_layout = QGridLayout()
        attrs_group_box.setLayout(attrs_layout)
        main_layout.addWidget(attrs_group_box, r, 0, 1, 2)
        attrs = []
        for label, checked in [
            ("Alignment", self.function.is_alignment),
            ("PLT", self.function.is_plt),
            ("SimProcedure", self.function.is_simprocedure),
            ("Returning", self.function.returning),
            ("Prototype Guessed", self.function.is_prototype_guessed),
            ("Variadic", self.function.prototype is not None and self.function.prototype.variadic),
        ]:
            cb = QCheckBox(label, self)
            cb.setChecked(checked)
            cb.setEnabled(False)  # FIXME: Support editing
            attrs.append(cb)
        add_to_grid(attrs_layout, 3, attrs)
        r += 1

        actions_group_box = QGroupBox("Actions")
        actions_layout = QGridLayout()
        actions_group_box.setLayout(actions_layout)
        main_layout.addWidget(actions_group_box, r, 0, 1, 2)
        actions = [
            ("&Decompile", self._decompile),
            ("Dis&assemble", self._disassemble),
            ("Show &Xrefs", self._show_xrefs),
            ("Show &Strings", self._show_strings),
            # FIXME: Create Call State
            # FIXME: Show Function Documentation
            # FIXME: Show In Proximity View
            # FIXME: Plugin extras
        ]
        action_buttons = []
        for label, handler in actions:
            btn = QPushButton(label, self)
            btn.clicked.connect(handler)
            action_buttons.append(btn)
        add_to_grid(actions_layout, 4, action_buttons)
        r += 1

        main_layout.setRowStretch(r, 1)
        r += 1

    def _decompile(self) -> None:
        self.workspace.decompile_function(self.function)
        self.accept()

    def _disassemble(self) -> None:
        self.workspace.jump_to(self.function.addr)
        self.accept()

    def _show_xrefs(self) -> None:
        # FIXME: Make this an action on workspace
        dialog = XRefDialog(
            addr=self.function.addr,
            dst_addr=self.function.addr,
            xrefs_manager=self.workspace.main_instance.project.kb.xrefs,
            instance=self.workspace.main_instance,
            parent=self,
        )
        dialog.exec_()
        self.accept()

    def _show_strings(self) -> None:
        self.workspace.show_strings_view()
        view = self.workspace.view_manager.first_view_in_category("strings")
        if view is not None:
            view.select_function(self.function)
        self.accept()
