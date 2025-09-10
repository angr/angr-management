from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QDialog,
    QGridLayout,
    QGroupBox,
    QPushButton,
)

from angrmanagement.logic import GlobalInfo
from angrmanagement.ui.dialogs.xref import XRefDialog
from angrmanagement.ui.views.strings_view import StringsView
from angrmanagement.ui.widgets.qproperty_editor import (
    BoolPropertyItem,
    GroupPropertyItem,
    PropertyModel,
    QPropertyEditor,
    TextPropertyItem,
)
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
        main_layout = QGridLayout()
        self.setLayout(main_layout)

        root = GroupPropertyItem("root")
        for label, text in [
            ("Name", self.function.name),
            ("Address", f"{self.function.addr:x}"),
            ("Binary", f"{self.function.binary}"),
            ("Offset", f"{self.function.offset:x}"),
            (
                "Calling Convention",
                "<Unknown>" if self.function.calling_convention is None else f"{self.function.calling_convention}",
            ),
            ("Tags", ", ".join(self.function.tags)),
            ("Cyclomatic Complexity", str(self.function.cyclomatic_complexity)),
            (
                "C Prototype",
                (
                    (self.function.prototype.c_repr(full=True).replace("()", self.function.name, 1) + ";")
                    if self.function.prototype
                    else ""
                ),
            ),
        ]:
            root.addChild(TextPropertyItem(label, text, readonly=True))  # FIXME: Support editing

        for label, checked in [
            ("Alignment", self.function.is_alignment),
            ("PLT", self.function.is_plt),
            ("SimProcedure", self.function.is_simprocedure),
            ("Returning", self.function.returning),
            ("Prototype Guessed", self.function.is_prototype_guessed),
            ("Variadic", self.function.prototype is not None and self.function.prototype.variadic),
        ]:
            root.addChild(BoolPropertyItem(label, checked, readonly=True))  # FIXME: Support editing

        r = 0

        self._model = PropertyModel(root)
        self._tree = QPropertyEditor()
        self._tree.set_description_visible(False)
        self._tree.setModel(self._model)
        main_layout.addWidget(self._tree, r, 0, 1, 2)
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

        main_layout.setRowStretch(r, 0)

    def sizeHint(self):  # pylint:disable=no-self-use
        return QSize(700, 500)

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
        if dialog.exec_():
            self.accept()

    def _show_strings(self) -> None:
        self.workspace.show_strings_view()
        view = self.workspace.view_manager.first_view_in_category("strings")
        if isinstance(view, StringsView):
            view.select_function(self.function)
        self.accept()
