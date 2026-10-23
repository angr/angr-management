from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from angrmanagement.config import Conf


class RuntimeBreakpointDialog(QDialog):
    """Configure executable breakpoints and hardware data watchpoints."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add runtime breakpoint")
        self.resize(520, 250)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        layout.addLayout(form)
        self.kind = QComboBox(self)
        for caption, kind in (
            ("Execution", "execute"),
            ("Memory write", "write"),
            ("Memory read", "read"),
            ("Memory access", "access"),
        ):
            self.kind.addItem(caption, kind)
        form.addRow("Break on", self.kind)
        self.location = QLineEdit(self)
        self.location.setFont(Conf.code_font)
        self.location.setPlaceholderText("main, file.c:42, or *0x…")
        form.addRow("Location / expression", self.location)
        self.condition = QLineEdit(self)
        self.condition.setPlaceholderText("Optional, e.g. score > 100")
        form.addRow("Condition", self.condition)
        self.temporary = QCheckBox("Remove after the first hit", self)
        form.addRow(self.temporary)
        hint = QLabel(
            "Memory watchpoints accept a GDB lvalue, such as score or *(int*)0x…. Hardware slots are limited.", self
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.error = QLabel(self)
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, self
        )
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.kind.currentIndexChanged.connect(self._kind_changed)

    def _kind_changed(self) -> None:
        execution = self.kind.currentData() == "execute"
        self.temporary.setEnabled(execution)
        if not execution:
            self.temporary.setChecked(False)
        self.location.setPlaceholderText("main, file.c:42, or *0x…" if execution else "score or *(int*)0x…")

    def configuration(self) -> dict:
        location = self.location.text().strip()
        if not location:
            raise ValueError("Enter a breakpoint location or memory expression.")
        return {
            "location": location,
            "kind": self.kind.currentData(),
            "condition": self.condition.text().strip() or None,
            "temporary": self.temporary.isChecked(),
        }

    def _accept(self) -> None:
        try:
            self.configuration()
        except ValueError as exc:
            self.error.setText(str(exc))
            return
        self.accept()
