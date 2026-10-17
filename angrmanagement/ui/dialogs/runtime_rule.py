from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
)

from angrmanagement.config import Conf
from angrmanagement.logic.debugger.gdb import RuntimeErrorBase

if TYPE_CHECKING:
    from angrmanagement.logic.debugger.gdb import GDBRuntime


class RuntimeRuleDialog(QDialog):
    """Review a live binding and the exact GDB actions it will install."""

    def __init__(
        self,
        runtime: GDBRuntime,
        expression: str = "",
        label: str = "",
        mode: str = "monitor",
        trigger: str | None = None,
        note: str = "",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.runtime = runtime
        self._editing = False
        self.setWindowTitle("Runtime variable")
        self.resize(660, 580)
        layout = QVBoxLayout(self)
        explanation = QLabel(note or "Choose a live value and decide what happens when it changes.", self)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        form = QFormLayout()
        layout.addLayout(form)
        self.label = QLineEdit(label, self)
        self.label.setPlaceholderText("A name for this variable")
        form.addRow("Label", self.label)
        self.expression = QLineEdit(expression, self)
        self.expression.setObjectName("runtime_binding")
        self.expression.setFont(Conf.code_font)
        self.expression.setPlaceholderText("score, *(int*)0x…, or $rax")
        form.addRow("GDB expression", self.expression)
        self.mode = QComboBox(self)
        for caption, key in (
            ("Monitor changes", "monitor"),
            ("Clamp to a value", "clamp"),
            ("Set once", "set"),
            ("Custom hook", "custom"),
        ):
            self.mode.addItem(caption, key)
        self.mode.setCurrentIndex(max(0, self.mode.findData(mode)))
        form.addRow("Action", self.mode)
        self.value = QLineEdit(self)
        self.value.setPlaceholderText("GDB value, such as 100 or 0xFF")
        form.addRow("Value", self.value)
        self.trigger = QLineEdit(trigger or "", self)
        self.trigger.setPlaceholderText("Optional instruction or function; blank = watch writes")
        form.addRow("Trigger", self.trigger)
        hint = QLabel(
            "A watchpoint follows writes to the expression. An execution trigger samples the value at that location. "
            "Hooks auto-continue; pause execution before editing them. Bindings expire when the session changes.",
            self,
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.commands = QPlainTextEdit(self)
        self.commands.setFont(Conf.code_font)
        self.commands.setPlaceholderText('One GDB command per line, e.g. printf "tick\\n"')
        self.commands.setMaximumHeight(130)
        layout.addWidget(self.commands)
        layout.addWidget(QLabel("Generated GDB commands", self))
        self.preview = QPlainTextEdit(self)
        self.preview.setObjectName("runtime_hook_preview")
        self.preview.setReadOnly(True)
        self.preview.setFont(Conf.code_font)
        self.preview.setMaximumHeight(150)
        layout.addWidget(self.preview)
        self.error = QLabel(self)
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self
        )
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.mode.currentIndexChanged.connect(self._update_preview)
        for field in (self.expression, self.value, self.trigger):
            field.textChanged.connect(self._update_preview)
        self.commands.textChanged.connect(self._update_preview)
        self._update_preview()

    def configuration(self) -> dict:
        expression = self.expression.text().strip()
        mode = self.mode.currentData()
        if not expression or "\n" in expression or "\r" in expression:
            raise ValueError("Enter a single GDB expression for the live variable.")
        value = self.value.text().strip()
        if mode in {"clamp", "set"} and not value:
            raise ValueError("Enter the value to write.")
        commands = self.commands.toPlainText().splitlines() if mode == "custom" else None
        if mode == "custom" and not any(line.strip() for line in commands or []):
            raise ValueError("Enter at least one custom GDB command.")
        return {
            "label": self.label.text().strip() or expression,
            "expression": expression,
            "mode": mode,
            "value": value or None,
            "trigger": self.trigger.text().strip() or None,
            "commands": commands,
        }

    def lock_binding(self) -> None:
        """Edit an existing custom script while keeping its installed location."""
        self._editing = True
        for field in (self.label, self.expression, self.trigger):
            field.setReadOnly(True)
        self.mode.setEnabled(False)
        self._update_preview()

    def _update_preview(self) -> None:
        mode = self.mode.currentData()
        self.value.setEnabled(mode in {"clamp", "set"})
        self.commands.setVisible(mode == "custom")
        self.trigger.setEnabled(mode != "set")
        caption = "Save hook" if self._editing else "Write value" if mode == "set" else "Add rule"
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText(caption)
        try:
            config = self.configuration()
            if mode == "set":
                commands = [f"set variable {config['expression']} = {config['value']}"]
            else:
                commands = self.runtime.preview_rule(
                    config["expression"], mode=mode, value=config["value"], commands=config["commands"]
                )
            self.preview.setPlainText("\n".join(commands))
            self.error.clear()
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        except (ValueError, RuntimeErrorBase) as exc:
            self.preview.clear()
            self.error.setText(str(exc))
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)

    def _accept(self) -> None:
        try:
            self.configuration()
        except ValueError as exc:
            self.error.setText(str(exc))
            return
        self.accept()
