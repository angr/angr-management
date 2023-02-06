from collections import OrderedDict
from typing import TYPE_CHECKING, Optional

from angr.analyses.decompiler.structured_codegen.c import CConstruct, CFunction, CFunctionCall, CStructField, CVariable
from angr.sim_type import NamedTypeMixin, SimType, SimTypePointer, TypeRef
from PySide6.QtGui import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QVBoxLayout,
)

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.ui.views.code_view import CodeView


class NodeNameBox(QLineEdit):
    """
    QLineEdit that validates node names.
    """

    def __init__(self, textchanged_callback, parent=None):
        super().__init__(parent)

        self.textChanged.connect(textchanged_callback)

    @property
    def name(self):
        text = self.text()
        if self._is_valid_node_name(text):
            return text.strip()
        return None

    @staticmethod
    def _is_valid_node_name(name):
        stripped = name.strip()
        return stripped and " " not in stripped


class RenameNode(QDialog):
    """
    Dialog for renaming a node.
    """

    def __init__(
        self,
        code_view: Optional["CodeView"] = None,
        node: Optional[CConstruct] = None,
        parent=None,
        func: Optional["Function"] = None,
    ):
        super().__init__(parent)

        # initialization
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self._code_view = code_view
        self._node = node
        self._func: Optional["Function"] = func

        self._name_box: NodeNameBox = None
        self._status_label = None
        self._ok_button: QPushButton = None
        self._suggestion_box: QListWidget = None

        self.setWindowTitle("Rename")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        if not isinstance(self._node, CVariable):
            self._suggestion_box.setEnabled(False)
        else:
            if self._node.unified_variable is not None:
                if not self._node.unified_variable.candidate_names:
                    self._suggestion_box.setEnabled(False)
                else:
                    for candidate in self._node.unified_variable.candidate_names:
                        self._suggestion_box.addItem(candidate)

        self.setLayout(self.main_layout)

    #
    # Private methods
    #

    def _init_widgets(self):
        # name label

        name_label = QLabel(self)
        name_label.setText("New name")

        name_box = NodeNameBox(self._on_name_changed, self)
        if self._node is not None:
            # parse node type, either a Function header or a Variable.
            if isinstance(self._node, CVariable) and self._node.unified_variable and self._node.unified_variable.name:
                name_box.setText(self._node.unified_variable.name)
            elif isinstance(self._node, CVariable) and not self._node.variable.region:
                name_box.setText(self._node.variable.name)
            elif isinstance(self._node, CFunction) and self._node.name:
                name_box.setText(self._node.name)
            elif isinstance(self._node, CFunctionCall):
                name_box.setText(self._node.callee_func.name)
            elif isinstance(self._node, CStructField):
                name_box.setText(self._node.field)

            name_box.selectAll()
        self._name_box = name_box

        label_layout = QHBoxLayout()
        label_layout.addWidget(name_label)
        label_layout.addWidget(name_box)
        self.main_layout.addLayout(label_layout)

        # suggestions
        suggest_label = QLabel(self)
        suggest_label.setText("Suggestions")

        suggestion_box = QListWidget()
        self._suggestion_box = suggestion_box
        suggestion_layout = QHBoxLayout()
        suggestion_layout.addWidget(suggest_label)
        suggestion_layout.addWidget(suggestion_box)
        self.main_layout.addLayout(suggestion_layout)

        # status label
        status_label = QLabel(self)
        self.main_layout.addWidget(status_label)
        self._status_label = status_label

        # buttons
        buttons = QDialogButtonBox(parent=self)
        buttons.setStandardButtons(QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self._on_ok_clicked)
        buttons.rejected.connect(self.close)
        self._ok_button = buttons.button(QDialogButtonBox.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_name_changed(self, new_text):  # pylint:disable=unused-argument
        if self._name_box is None:
            # initialization is not done yet
            return

        if self._name_box.name is None:
            # the variable name is invalid
            self._status_label.setText("Invalid")
            self._status_label.setProperty("class", "status_invalid")
            self._ok_button.setEnabled(False)
        else:
            self._status_label.setText("Valid")
            self._status_label.setProperty("class", "status_valid")
            self._ok_button.setEnabled(True)

        self._status_label.style().unpolish(self._status_label)
        self._status_label.style().polish(self._status_label)

    def _on_ok_clicked(self):
        node_name = self._name_box.name
        if node_name is not None:
            if self._code_view is not None and self._node is not None:
                # need workspace for altering callbacks of changes
                workspace = self._code_view.instance.workspace
                code_kb = self._code_view.codegen.kb

                # stack variable
                if isinstance(self._node, CVariable) and self._node.unified_variable is not None:
                    # sanity check that we are a stack var
                    if hasattr(self._node.variable, "offset") and self._node.variable.offset is not None:
                        workspace.plugins.handle_stack_var_renamed(
                            self._func,
                            self._node.variable.offset,
                            self._node.variable.name,
                            node_name,
                        )

                    self._node.unified_variable.name = node_name
                    self._node.unified_variable.renamed = True

                # global variable
                elif isinstance(self._node, CVariable) and not self._node.variable.region:
                    workspace.plugins.handle_global_var_renamed(
                        self._node.variable.addr, self._node.variable.name, node_name
                    )

                    self._code_view.instance.kb.labels[self._node.variable.addr] = node_name
                    self._node.variable.name = node_name
                    self._node.variable.renamed = True

                # function arg
                elif isinstance(self._node, CVariable):
                    workspace.plugins.handle_func_arg_renamed(
                        code_kb.functions[self._node.codegen.cfunc.addr], 0, self._node.variable.name, node_name
                    )

                    self._node.variable.name = node_name
                    self._node.variable.renamed = True

                # function name
                elif isinstance(self._node, CFunction):
                    workspace.plugins.handle_function_renamed(
                        code_kb.functions[self._node.codegen.cfunc.addr], self._node.name, node_name
                    )

                    code_kb.functions.get_by_addr(self._node.addr).name = node_name
                    self._node.name = node_name
                    self._node.demangled_name = node_name

                # function renaming (as a call)
                elif isinstance(self._node, CFunctionCall):
                    if self._node.callee_func is not None:
                        workspace.plugins.handle_function_renamed(
                            code_kb.functions[self._node.codegen.cfunc.addr], self._node.callee_func.name, node_name
                        )

                        self._node.callee_func.name = node_name

                # struct renaming
                elif isinstance(self._node, CStructField):
                    # TODO add a better callback
                    # TODO prevent name duplication. reuse logic from CTypeEditor?
                    # TODO if this is a temporary struct, make it permanent and add it to kb.types
                    fields = [
                        (node_name if n == self._node.field else n, t) for n, t in self._node.struct_type.fields.items()
                    ]
                    self._node.struct_type.fields = OrderedDict(fields)

                    workspace.plugins.handle_struct_changed(self._node.field, node_name)

                    self._node.field = node_name

                elif isinstance(self._node, SimType):
                    ty = self._node
                    ref = None
                    while True:
                        if isinstance(ty, TypeRef):
                            ref = ty
                            ty = ty.type
                        elif isinstance(ty, SimTypePointer):
                            ref = None
                            ty = ty.pts_to
                        else:
                            break
                    if isinstance(ty, NamedTypeMixin):
                        ty.name = node_name
                        if ref is not None:  # update the typeref as well
                            ref._name = node_name
                    else:
                        ty.label = node_name

                self._code_view.codegen.am_event()
                self.close()
