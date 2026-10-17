from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen import (
    CodegenNode,
    VariableNode,
)
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

from angrmanagement.present.code import CodePresenter, is_valid_node_name, rename_default, rename_node_directly

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function

    from angrmanagement.ui.views.code_view import CodeView


class NodeNameBox(QLineEdit):
    """
    QLineEdit that validates node names.
    """

    def __init__(self, textchanged_callback, parent=None) -> None:
        super().__init__(parent)

        self.textChanged.connect(textchanged_callback)

    @property
    def name(self):
        text = self.text()
        if self._is_valid_node_name(text):
            return text.strip()
        return None

    @staticmethod
    def _is_valid_node_name(name: str):
        return is_valid_node_name(name)


class RenameNode(QDialog):
    """
    Dialog for renaming a node.
    """

    def __init__(
        self,
        code_view: CodeView | None = None,
        node: CodegenNode | None = None,
        parent=None,
        func: Function | None = None,
    ) -> None:
        super().__init__(parent)

        # initialization
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

        self._code_view = code_view
        self._node = node
        self._func: Function | None = func

        self._name_box: NodeNameBox = None
        self._status_label = None
        self._ok_button: QPushButton = None
        self._suggestion_box: QListWidget = None

        self.setWindowTitle("Rename")

        self.main_layout = QVBoxLayout()

        self._init_widgets()

        if not isinstance(self._node, VariableNode):
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

    def _init_widgets(self) -> None:
        # name label

        name_label = QLabel(self)
        name_label.setText("New name")

        name_box = NodeNameBox(self._on_name_changed, self)
        if self._node is not None:
            # parse node type, either a Function header or a Variable.
            name = rename_default(self._node)
            if name:
                name_box.setText(name)
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
        self._ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok_button.setEnabled(False)
        self.main_layout.addWidget(buttons)

    #
    # Event handlers
    #

    def _on_name_changed(self, _) -> None:
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

    def _on_ok_clicked(self) -> None:
        node_name = self._name_box.name
        if node_name is not None and self._code_view is not None and self._node is not None:
            if self._code_view.codegen.cfunc is None:
                self.close()
                return
            presenter = getattr(self._code_view, "presenter", None)
            if isinstance(presenter, CodePresenter):
                presenter.apply_rename(self._node, node_name, self._func)
            else:
                rename_node_directly(
                    self._code_view.workspace,
                    self._code_view.instance,
                    self._code_view.codegen,
                    self._node,
                    node_name,
                    self._func,
                )
            self._code_view.codegen.am_event()
            self.close()
