from __future__ import annotations

import os
import shlex
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from typing import Any


class RuntimeConnectionDialog(QDialog):
    """Describe a GDB target without starting it until the form is accepted."""

    def __init__(self, executable: str = "", gdb_path: str = "gdb", parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Connect runtime debugger")
        self.resize(620, 440)
        layout = QVBoxLayout(self)
        heading = QLabel("Run the binary you are analyzing", self)
        font = heading.font()
        font.setPointSize(font.pointSize() + 3)
        font.setBold(True)
        heading.setFont(font)
        layout.addWidget(heading)
        hint = QLabel("GDB controls execution. Runtime addresses are resolved from the process's loaded modules.", self)
        hint.setWordWrap(True)
        layout.addWidget(hint)
        form = QFormLayout()
        layout.addLayout(form)
        self.mode = QComboBox(self)
        self.mode.addItem("Launch a program", "launch")
        self.mode.addItem("Attach to a process", "attach")
        self.mode.addItem("Connect to gdbserver", "remote")
        form.addRow("Session", self.mode)
        self.executable = QLineEdit(executable, self)
        self.executable.setObjectName("runtime_executable")
        self.executable.setPlaceholderText("Executable / local symbols for the target")
        form.addRow("Executable", self._file_field(self.executable, "Select executable"))
        self.gdb_path = QLineEdit(gdb_path, self)
        form.addRow("GDB executable", self._file_field(self.gdb_path, "Select GDB executable"))
        self.args = QLineEdit(self)
        self.args.setPlaceholderText('Arguments, with shell-style quoting; e.g. --level "Ice caves"')
        form.addRow("Arguments", self.args)
        self.cwd = QLineEdit(os.path.dirname(executable) if executable else "", self)
        form.addRow("Working directory", self.cwd)
        self.env = QPlainTextEdit(self)
        self.env.setMaximumHeight(90)
        self.env.setPlaceholderText("Optional environment overrides, one NAME=value per line")
        form.addRow("Environment", self.env)
        self.pid = QSpinBox(self)
        self.pid.setRange(1, 2147483647)
        form.addRow("Process ID", self.pid)
        self.endpoint = QLineEdit("localhost:1234", self)
        form.addRow("gdbserver endpoint", self.endpoint)
        self.stop_at_entry = QCheckBox("Stop at the first instruction (including the dynamic loader)", self)
        self.stop_at_entry.setChecked(True)
        form.addRow(self.stop_at_entry)
        self.error = QLabel(self)
        self.error.setWordWrap(True)
        self.error.setAccessibleName("Connection validation error")
        layout.addWidget(self.error)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok, self
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Connect")
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self._mode_changed()

    def _file_field(self, field: QLineEdit, title: str) -> QWidget:
        widget = QWidget(self)
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(field)
        button = QPushButton("Browse…", widget)
        button.clicked.connect(lambda: self._browse(field, title))
        layout.addWidget(button)
        return widget

    def _browse(self, field: QLineEdit, title: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, title, field.text())
        if path:
            field.setText(path)

    def _mode_changed(self) -> None:
        mode = self.mode.currentData()
        for widget in (self.args, self.cwd, self.env, self.stop_at_entry):
            widget.setEnabled(mode == "launch")
        self.pid.setEnabled(mode == "attach")
        self.endpoint.setEnabled(mode == "remote")

    def configuration(self) -> tuple[str, dict[str, Any]]:
        """Validate and return the service method and keyword arguments."""
        if not self.gdb_path.text().strip():
            raise ValueError("Choose a GDB executable, or enter gdb to use PATH.")
        executable = self.executable.text().strip()
        mode = self.mode.currentData()
        if mode == "launch":
            if not executable:
                raise ValueError("Choose the executable to launch.")
            env = {}
            for line in self.env.toPlainText().splitlines():
                if not line.strip():
                    continue
                name, sep, value = line.partition("=")
                if not sep or not name or any(c.isspace() for c in name):
                    raise ValueError("Environment overrides must use NAME=value, one per line.")
                env[name] = value
            return "launch", {
                "executable": executable,
                "args": shlex.split(self.args.text()),
                "cwd": self.cwd.text().strip() or None,
                "env": env or None,
                "stop_at_entry": self.stop_at_entry.isChecked(),
            }
        if mode == "attach":
            return "attach", {"pid": self.pid.value(), "executable": executable or None}
        endpoint = self.endpoint.text().strip()
        if not endpoint:
            raise ValueError("Enter a gdbserver endpoint, such as localhost:1234.")
        return "connect_remote", {"endpoint": endpoint, "executable": executable or None}

    def _accept(self) -> None:
        try:
            self.configuration()
        except ValueError as exc:
            self.error.setText(str(exc))
            return
        self.accept()
