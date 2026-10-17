from __future__ import annotations

import math
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QObject, QPointF, Qt, QTimer, Signal
from PySide6.QtGui import QPainter, QPainterPath, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.config import Conf
from angrmanagement.logic.debugger.variable_binding import verify_module_identity
from angrmanagement.ui.dialogs.runtime_breakpoint import RuntimeBreakpointDialog
from angrmanagement.ui.dialogs.runtime_connection import RuntimeConnectionDialog
from angrmanagement.ui.dialogs.runtime_rule import RuntimeRuleDialog

from .view import InstanceView

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.debugger.gdb import GDBRuntime
    from angrmanagement.ui.workspace import Workspace


class _RuntimeSignals(QObject):
    """Carry worker results and backend notifications onto the GUI thread."""

    runtime_event = Signal(str, object)
    completed = Signal(object)


class RuntimeHistoryChart(QWidget):
    """A compact numeric trace of actual hook samples, using the current theme."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(100)
        self.setMaximumHeight(160)
        self._values: list[float] = []
        self._caption = "Select a variable to see its recent values"
        self.setAccessibleName("Runtime variable history")

    def set_samples(self, samples: list, caption: str = "") -> None:
        values = []
        for sample in samples:
            value = sample.get("value") if isinstance(sample, dict) else sample
            try:
                text = str(value).split()[0]
                number = float(int(text, 0)) if text.lower().startswith(("0x", "-0x")) else float(text)
            except (ValueError, IndexError, TypeError, OverflowError):
                continue
            if math.isfinite(number):
                values.append(number)
        self._values = values[-200:]
        self._caption = caption or "Waiting for numeric samples"
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette()
        painter.fillRect(self.rect(), palette.brush(QPalette.ColorRole.Base))
        painter.setPen(palette.color(QPalette.ColorRole.Text))
        painter.drawText(12, 20, self._caption)
        if not self._values:
            painter.setPen(palette.color(QPalette.ColorRole.PlaceholderText))
            painter.drawText(12, 48, "No numeric samples yet; raw values appear in Activity.")
            return
        lo, hi = min(self._values), max(self._values)
        left, top, width, height = 12, 40, max(1, self.width() - 24), max(1, self.height() - 60)
        painter.setPen(palette.color(QPalette.ColorRole.Mid))
        painter.drawLine(left, top + height, left + width, top + height)
        path = QPainterPath()
        points = []
        for index, value in enumerate(self._values):
            x = left + index * width / max(1, len(self._values) - 1)
            y = top + height / 2 if hi == lo else top + height - (value - lo) * height / (hi - lo)
            points.append(QPointF(x, y))
        path.moveTo(points[0])
        for point in points[1:]:
            path.lineTo(point)
        pen = painter.pen()
        pen.setColor(palette.color(QPalette.ColorRole.Highlight))
        pen.setWidthF(2)
        painter.setPen(pen)
        painter.drawPath(path)
        if len(points) == 1:
            painter.drawEllipse(points[0], 2, 2)
        painter.setPen(palette.color(QPalette.ColorRole.PlaceholderText))
        painter.drawText(left, self.height() - 4, f"min {lo:g}    max {hi:g}    latest {self._values[-1]:g}")


class RuntimeView(InstanceView):
    """Live process controls and inspectors; GDB requests run off the GUI thread."""

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("runtime", workspace, default_docking_position, instance)
        self.base_caption = "Runtime"
        self.runtime: GDBRuntime = workspace.runtime
        self.width_hint = 1120
        self.height_hint = 720
        self._snapshot: dict[str, Any] = {}
        self._busy = False
        self._pending = 0
        self._closed = False
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="runtime-ui")
        self._signals = _RuntimeSignals(self)
        self._signals.runtime_event.connect(self._on_event)
        self._signals.completed.connect(self._on_completed)
        self._unsubscribe = self.runtime.subscribe(self._service_event)
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(75)
        self._render_timer.timeout.connect(self.refresh)
        self._stopped_controls: list[QWidget] = []
        self._init_widgets()
        self.refresh()

    @staticmethod
    def _button(text: str, callback: Callable, layout, tooltip: str = "") -> QPushButton:
        button = QPushButton(text)
        button.setToolTip(tooltip)
        button.clicked.connect(callback)
        layout.addWidget(button)
        return button

    @staticmethod
    def _table(columns: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.verticalHeader().hide()
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    @staticmethod
    def _panel() -> tuple[QWidget, QVBoxLayout]:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        return panel, layout

    def _init_widgets(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        header = QHBoxLayout()
        title = QLabel("Runtime")
        font = title.font()
        font.setPointSize(font.pointSize() + 6)
        font.setBold(True)
        title.setFont(font)
        header.addWidget(title)
        self.state_label = QLabel("DISCONNECTED")
        self.state_label.setObjectName("runtime_state")
        self.state_label.setMargin(7)
        self.state_label.setFrameShape(QFrame.Shape.StyledPanel)
        self.state_label.setAutoFillBackground(True)
        state_font = self.state_label.font()
        state_font.setBold(True)
        self.state_label.setFont(state_font)
        header.addWidget(self.state_label)
        header.addStretch()
        self.connect_button = self._button("Connect…", self._connect, header)
        self.refresh_button = self._button("Refresh", lambda: self.submit("refresh"), header)
        layout.addLayout(header)
        self.target_label = QLabel("Launch a program, attach to a process, or connect to gdbserver.")
        self.target_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.target_label.setWordWrap(True)
        layout.addWidget(self.target_label)
        controls = QHBoxLayout()
        controls.setSpacing(6)
        self.continue_button = self._button(
            "▶ Continue", lambda: self.submit("continue_execution"), controls, "Resume execution"
        )
        self.pause_button = self._button("Ⅱ Pause", lambda: self.submit("interrupt"), controls, "Interrupt the target")
        self.step_button = self._button(
            "Step into", lambda: self.submit("step_instruction"), controls, "Execute one instruction"
        )
        self.next_button = self._button(
            "Step over", lambda: self.submit("next_instruction"), controls, "Step over calls"
        )
        self.finish_button = self._button(
            "Step out", lambda: self.submit("finish"), controls, "Run until the current frame returns"
        )
        self.pc_button = self._button(
            "Show PC", self._show_pc, controls, "Map the stopped program counter into the analysis"
        )
        controls.addStretch()
        self.detach_button = self._button("Detach", lambda: self.submit("detach"), controls)
        self.stop_button = self._button("Stop", lambda: self.submit("stop"), controls, "Terminate the debugged program")
        layout.addLayout(controls)
        self.error_label = QLabel()
        self.error_label.setObjectName("runtime_error")
        self.error_label.setProperty("class", "status_invalid")
        self.error_label.setWordWrap(True)
        self.error_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.error_label.hide()
        layout.addWidget(self.error_label)
        self._stopped_controls += [
            self.continue_button,
            self.step_button,
            self.next_button,
            self.finish_button,
            self.pc_button,
        ]

        vertical = QSplitter(Qt.Orientation.Vertical)
        main = QSplitter(Qt.Orientation.Horizontal)
        watches, watch_layout = self._panel()
        watch_header = QHBoxLayout()
        watch_header.addWidget(QLabel("WATCHES & RULES"))
        watch_header.addStretch()
        # Discard QPushButton.clicked's checked argument before open_binding's expression argument.
        self.add_rule_button = self._button(
            "+ Variable",
            lambda: self.open_binding(),  # pylint: disable=unnecessary-lambda
            watch_header,
        )
        self.custom_hook_button = self._button("+ Hook", lambda: self.open_binding(mode="custom"), watch_header)
        self._stopped_controls += [self.add_rule_button, self.custom_hook_button]
        watch_layout.addLayout(watch_header)
        self.watch_hint = QLabel(
            "Select a variable in the decompiler, then choose Runtime → Monitor or Clamp. "
            "You can also add a GDB expression here."
        )
        self.watch_hint.setWordWrap(True)
        watch_layout.addWidget(self.watch_hint)
        self.rules_table = self._table(["Variable", "Latest value", "Policy", "Samples"])
        self.rules_table.setObjectName("runtime_rules")
        self.rules_table.setColumnWidth(0, 160)
        self.rules_table.setColumnWidth(1, 120)
        self.rules_table.itemSelectionChanged.connect(self._rule_selected)
        self.rules_table.cellDoubleClicked.connect(self._edit_rule)
        watch_layout.addWidget(self.rules_table, 1)
        self.chart = RuntimeHistoryChart()
        watch_layout.addWidget(self.chart)
        rule_actions = QHBoxLayout()
        self.toggle_rule_button = self._button("Disable", self._toggle_rule, rule_actions)
        self.edit_rule_button = self._button("Change value…", self._edit_rule, rule_actions)
        self.remove_rule_button = self._button("Remove", self._remove_rule, rule_actions)
        rule_actions.addStretch()
        self._button("Copy commands", self._copy_rule, rule_actions)
        watch_layout.addLayout(rule_actions)
        self.rule_preview = QPlainTextEdit()
        self.rule_preview.setReadOnly(True)
        self.rule_preview.setFont(Conf.code_font)
        self.rule_preview.setMaximumHeight(100)
        self.rule_preview.setPlaceholderText("Select a rule to inspect its generated GDB commands.")
        watch_layout.addWidget(self.rule_preview)
        main.addWidget(watches)

        inspector_panel, inspector_layout = self._panel()
        inspector_layout.setContentsMargins(0, 0, 0, 0)
        self.snapshot_hint = QLabel("Last paused snapshot · Pause to refresh registers, threads and memory maps.")
        self.snapshot_hint.setWordWrap(True)
        inspector_layout.addWidget(self.snapshot_hint)
        self.inspectors = QTabWidget()
        self.inspectors.setObjectName("runtime_inspectors")
        self._init_inspectors()
        inspector_layout.addWidget(self.inspectors)
        main.addWidget(inspector_panel)
        main.setSizes([480, 620])
        vertical.addWidget(main)
        self.bottom_tabs = QTabWidget()
        self._init_activity()
        vertical.addWidget(self.bottom_tabs)
        vertical.setSizes([510, 210])
        layout.addWidget(vertical, 1)
        self.footer = QLabel("GDB backend · Bindings are scoped to this process session")
        layout.addWidget(self.footer)

    def _init_inspectors(self) -> None:
        # Widgets are initialized by this constructor helper.
        # pylint: disable=attribute-defined-outside-init
        threads, thread_layout = self._panel()
        thread_layout.addWidget(QLabel("Double-click a thread or frame to select it."))
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.threads_table = self._table(["Thread", "State", "Location"])
        self.threads_table.cellDoubleClicked.connect(self._select_thread)
        splitter.addWidget(self.threads_table)
        self.frames_table = self._table(["Frame", "Function", "Runtime PC"])
        self.frames_table.setColumnWidth(0, 65)
        self.frames_table.setColumnWidth(1, 200)
        self.frames_table.cellDoubleClicked.connect(self._select_frame)
        splitter.addWidget(self.frames_table)
        thread_layout.addWidget(splitter)
        source_controls = QHBoxLayout()
        self.source_step_button = self._button("Step source", lambda: self.submit("step_source"), source_controls)
        self.source_next_button = self._button("Next source", lambda: self.submit("next_source"), source_controls)
        self._stopped_controls += [self.source_step_button, self.source_next_button]
        source_controls.addStretch()
        thread_layout.addLayout(source_controls)
        self.inspectors.addTab(threads, "Threads / stack")

        registers, registers_layout = self._panel()
        registers_layout.addWidget(QLabel("Double-click a register to write a new value while paused."))
        self.register_filter = QLineEdit()
        self.register_filter.setPlaceholderText("Filter registers…")
        registers_layout.addWidget(self.register_filter)
        self.registers_table = self._table(["Register", "Value"])
        self.register_filter.textChanged.connect(lambda text: self._filter_table(self.registers_table, text))
        self.registers_table.cellDoubleClicked.connect(self._edit_register)
        registers_layout.addWidget(self.registers_table)
        self.inspectors.addTab(registers, "Registers")

        modules, modules_layout = self._panel()
        modules_layout.addWidget(QLabel("Actual loaded ranges and ELF load bias; addresses include ASLR."))
        self.module_filter = QLineEdit()
        self.module_filter.setPlaceholderText("Filter modules…")
        modules_layout.addWidget(self.module_filter)
        self.modules_table = self._table(["Module", "Runtime start", "Runtime end", "Load bias"])
        self.module_filter.textChanged.connect(lambda text: self._filter_table(self.modules_table, text))
        self.modules_table.setColumnWidth(0, 190)
        self.modules_table.setColumnWidth(1, 155)
        self.modules_table.setColumnWidth(2, 155)
        modules_layout.addWidget(self.modules_table)
        self.module_warning = QLabel()
        self.module_warning.setWordWrap(True)
        modules_layout.addWidget(self.module_warning)
        base_row = QHBoxLayout()
        base_row.addWidget(QLabel("Analysis module base"))
        self.module_static_base = QLineEdit()
        self.module_static_base.setPlaceholderText("Main binary base, or explicit base for another module")
        base_row.addWidget(self.module_static_base)
        modules_layout.addLayout(base_row)
        mapping_row = QHBoxLayout()
        self.static_address = QLineEdit()
        self.static_address.setPlaceholderText("Analysis address, e.g. 0x401000")
        mapping_row.addWidget(self.static_address)
        self.map_button = self._button("Map to runtime", self._map_address, mapping_row)
        self._stopped_controls.append(self.map_button)
        modules_layout.addLayout(mapping_row)
        self.mapping_label = QLabel(
            "Select a module to map its analysis addresses; the main executable is the default."
        )
        self.mapping_label.setWordWrap(True)
        self.mapping_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        modules_layout.addWidget(self.mapping_label)
        self.inspectors.addTab(modules, "Modules")

        mappings, mappings_layout = self._panel()
        mappings_layout.addWidget(QLabel("Double-click a readable range to inspect it in Memory."))
        self.mapping_filter = QLineEdit()
        self.mapping_filter.setPlaceholderText("Filter ranges, permissions, or paths…")
        mappings_layout.addWidget(self.mapping_filter)
        self.mappings_table = self._table(["Start", "End", "Access", "Mapping"])
        self.mappings_table.setColumnWidth(0, 155)
        self.mappings_table.setColumnWidth(1, 155)
        self.mappings_table.setColumnWidth(2, 65)
        self.mapping_filter.textChanged.connect(lambda text: self._filter_table(self.mappings_table, text))
        self.mappings_table.cellDoubleClicked.connect(self._open_mapping)
        mappings_layout.addWidget(self.mappings_table)
        self.inspectors.addTab(mappings, "Mappings")

        memory, memory_layout = self._panel()
        self.memory_panel = memory
        memory_controls = QHBoxLayout()
        self.memory_address = QLineEdit()
        self.memory_address.setObjectName("runtime_memory_address")
        self.memory_address.setPlaceholderText("Runtime address or GDB expression, e.g. $rsp")
        memory_controls.addWidget(self.memory_address, 1)
        self.memory_size = QSpinBox()
        self.memory_size.setRange(1, 65536)
        self.memory_size.setValue(256)
        self.memory_size.setSuffix(" bytes")
        memory_controls.addWidget(self.memory_size)
        self.read_memory_button = self._button("Read", self._read_memory, memory_controls)
        memory_layout.addLayout(memory_controls)
        self.memory_text = QPlainTextEdit()
        self.memory_text.setObjectName("runtime_memory")
        self.memory_text.setReadOnly(True)
        self.memory_text.setFont(Conf.code_font)
        self.memory_text.setPlaceholderText("Pause execution, enter an address, and read live process memory.")
        memory_layout.addWidget(self.memory_text)
        memory_footer = QHBoxLayout()
        self.write_memory_button = self._button("Write bytes…", self._write_memory, memory_footer)
        memory_footer.addStretch()
        memory_footer.addWidget(QLabel("Writes affect the live process."))
        memory_layout.addLayout(memory_footer)
        self._stopped_controls += [self.read_memory_button, self.write_memory_button]
        self.inspectors.addTab(memory, "Memory")

    def _init_activity(self) -> None:
        # Widgets are initialized by this constructor helper.
        # pylint: disable=attribute-defined-outside-init
        activity, activity_layout = self._panel()
        self.events_table = self._table(["Time", "Event", "Details"])
        self.events_table.setColumnWidth(0, 160)
        self.events_table.setColumnWidth(1, 110)
        activity_layout.addWidget(self.events_table)
        self.bottom_tabs.addTab(activity, "Activity")
        breakpoints, breakpoint_layout = self._panel()
        self.breakpoints_table = self._table(["ID", "Enabled", "Kind", "Location", "Condition"])
        breakpoint_layout.addWidget(self.breakpoints_table)
        actions = QHBoxLayout()
        self.add_breakpoint_button = self._button("+ Breakpoint…", self._add_breakpoint, actions)
        self.toggle_breakpoint_button = self._button("Enable / disable", self._toggle_breakpoint, actions)
        self.remove_breakpoint_button = self._button("Remove", self._remove_breakpoint, actions)
        actions.addStretch()
        breakpoint_layout.addLayout(actions)
        self._stopped_controls += [
            self.add_breakpoint_button,
            self.toggle_breakpoint_button,
            self.remove_breakpoint_button,
        ]
        self.bottom_tabs.addTab(breakpoints, "Breakpoints")
        console, console_layout = self._panel()
        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setMaximumBlockCount(1000)
        self.console_output.setFont(Conf.code_font)
        console_layout.addWidget(self.console_output)
        command_row = QHBoxLayout()
        self.console_input = QLineEdit()
        self.console_input.setObjectName("runtime_console_command")
        self.console_input.setFont(Conf.code_font)
        self.console_input.setPlaceholderText("GDB command, e.g. info locals or set variable score = 100")
        self.console_input.returnPressed.connect(self._console_command)
        command_row.addWidget(self.console_input)
        self.console_run_button = self._button("Run", self._console_command, command_row)
        self.console_script_button = self._button("Script…", self._console_script, command_row)
        console_layout.addLayout(command_row)
        self._stopped_controls += [self.console_run_button, self.console_script_button, self.console_input]
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Program input"))
        self.target_input = QLineEdit()
        self.target_input.setObjectName("runtime_target_input")
        self.target_input.setPlaceholderText("Text sent to the program's terminal")
        self.target_input.returnPressed.connect(self._send_input)
        target_row.addWidget(self.target_input)
        self.target_newline = QCheckBox("Newline")
        self.target_newline.setChecked(True)
        target_row.addWidget(self.target_newline)
        self.target_send_button = self._button("Send", self._send_input, target_row)
        console_layout.addLayout(target_row)
        self.bottom_tabs.addTab(console, "GDB / program I/O")

    def submit(
        self,
        method: str,
        *args,
        on_result: Callable | None = None,
        expected_generation: int | None = None,
        expected_pc: int | None = None,
        expected_thread: str | None = None,
        expected_frame: int | None = None,
        **kwargs,
    ) -> None:
        """Queue one service operation; callbacks run on the GUI thread."""

        def operation():
            result = getattr(self.runtime, method)(*args, **kwargs)
            if method in {"write_register", "execute_console"} and self.runtime.snapshot().get("state") == "stopped":
                self.runtime.refresh()
            return result

        guarded = {
            "execute_console",
            "add_rule",
            "update_rule",
            "remove_rule",
            "add_breakpoint",
            "remove_breakpoint",
            "enable_breakpoint",
            "write_register",
            "select_thread",
            "select_frame",
            "continue_execution",
            "step_instruction",
            "next_instruction",
            "step_source",
            "next_source",
            "finish",
            "interrupt",
            "detach",
            "stop",
            "send_input",
        }
        if method in guarded:
            generation = (
                self.runtime.snapshot().get("generation", 0) if expected_generation is None else expected_generation
            )

            def call():
                states = (
                    {"running", "stopped"} if method in {"interrupt", "detach", "stop", "send_input"} else {"stopped"}
                )
                return self.runtime.checked(
                    operation,
                    generation,
                    expected_pc,
                    states=states,
                    thread_id=expected_thread,
                    frame_level=expected_frame,
                )
        else:
            call = operation
        self._call(call, method.replace("_", " "), on_result)

    def _call(self, operation: Callable, description: str, on_result: Callable | None = None) -> None:
        if self._closed:
            return
        self._pending += 1
        self._busy = True
        self.error_label.hide()
        self.footer.setText(f"GDB · {description}…")
        self._update_controls()

        def run() -> None:
            if self._closed:
                return
            result, error = None, None
            try:
                result = operation()
            # User scripts and remote targets may produce arbitrary failures.
            except Exception as exc:  # pylint: disable=broad-exception-caught
                error = str(exc) or type(exc).__name__
            if not self._closed:
                self._signals.completed.emit((result, error, on_result))

        self._executor.submit(run)

    def _on_completed(self, completion: tuple) -> None:
        if self._closed:
            return
        result, error, callback = completion
        self._pending -= 1
        self._busy = self._pending > 0
        self.refresh()
        if error:
            self._show_error(error)
        elif callback:
            try:
                callback(result)
            # A failed completion callback must not unwind through Qt's event loop.
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self._show_error(str(exc) or type(exc).__name__)
        self._update_footer()

    def _service_event(self, event: str, payload: dict) -> None:
        if not self._closed:
            self._signals.runtime_event.emit(event, payload)

    def _on_event(self, event: str, payload: dict) -> None:
        if self._closed:
            return
        if event == "error":
            self._show_error(str(payload.get("message", payload)))
        if not self._render_timer.isActive():
            self._render_timer.start()
        if event == "state" and payload.get("state") == "stopped" and not self._busy:
            self.submit("refresh")

    def refresh(self) -> None:
        if self._closed:
            return
        self._snapshot = self.runtime.snapshot()
        state = self._snapshot.get("state", "disconnected")
        self.state_label.setText(state.upper())
        palette = self.palette()
        palette.setColor(
            QPalette.ColorRole.Window,
            palette.color(QPalette.ColorRole.Highlight if state == "stopped" else QPalette.ColorRole.AlternateBase),
        )
        palette.setColor(
            QPalette.ColorRole.WindowText,
            palette.color(QPalette.ColorRole.HighlightedText if state == "stopped" else QPalette.ColorRole.Text),
        )
        self.state_label.setPalette(palette)
        self.state_label.setToolTip(str(self._snapshot.get("stop_reason") or ""))
        executable = self._snapshot.get("executable")
        if executable:
            frame = self._snapshot.get("frame") or {}
            pc = frame.get("addr")
            location = (
                f" · {frame.get('func', '?')} @ {self._hex(pc)}"
                if pc is not None and state in {"running", "stopped"}
                else ""
            )
            architecture = self._snapshot.get("architecture")
            architecture = f" · {architecture}" if architecture else ""
            filename = str(executable).replace("\\", "/").rsplit("/", 1)[-1]
            self.target_label.setText(f"{filename} · PID {self._snapshot.get('pid') or '—'}{architecture}{location}")
            self.target_label.setToolTip(str(executable))
        else:
            self.target_label.setText("Launch a program, attach to a process, or connect to gdbserver.")
            self.target_label.setToolTip("")
        self.snapshot_hint.setVisible(state == "running")
        self._render_rules()
        self._render_inspectors()
        self._render_activity()
        self._update_controls()
        if not self._busy:
            self._update_footer()

    def _update_footer(self) -> None:
        if self._busy:
            return
        if self._snapshot.get("state") == "running":
            self.footer.setText("Running · Hooks are active. Registers and stack show the last paused snapshot.")
        else:
            self.footer.setText("GDB backend · Bindings are scoped to this process session")

    @staticmethod
    def _hex(value) -> str:
        if value is None:
            return "—"
        if isinstance(value, int):
            return f"{value:#x}"
        return str(value)

    @staticmethod
    def _populate(table: QTableWidget, rows: list[tuple[Any, list[str], str]]) -> None:
        selected = RuntimeView._selected_id(table)
        scrollbar = table.verticalScrollBar()
        scroll = scrollbar.value()
        table.blockSignals(True)
        table.clearSelection()
        table.setRowCount(len(rows))
        select_row = None
        for row, (key, values, tooltip) in enumerate(rows):
            for column, value in enumerate(values):
                old = table.item(row, column)
                item = QTableWidgetItem(str(value))
                item.setData(Qt.ItemDataRole.UserRole, key)
                item.setToolTip(tooltip or str(value))
                if old is not None and old.data(Qt.ItemDataRole.UserRole) == key and old.text() != str(value):
                    item.setForeground(table.palette().color(QPalette.ColorRole.Link))
                table.setItem(row, column, item)
            if key == selected:
                select_row = row
        if select_row is not None:
            table.selectRow(select_row)
        table.blockSignals(False)
        scrollbar.setValue(scroll)

    @staticmethod
    def _selected_id(table: QTableWidget):
        items = table.selectedItems()
        return items[0].data(Qt.ItemDataRole.UserRole) if items else None

    def _render_rules(self) -> None:
        rows = []
        for rule in self._snapshot.get("rules", []):
            samples = rule.get("samples") or []
            count = len(samples) if isinstance(samples, list) else samples
            policy = str(rule.get("mode", "monitor"))
            if policy == "clamp":
                policy = f"Clamp → {rule.get('value')}"
            if not rule.get("enabled", True):
                policy = f"Paused · {policy}"
            if rule.get("error"):
                policy = f"Error · {rule['error']}"
            rows.append(
                (
                    rule["id"],
                    [rule.get("label", ""), rule.get("last_value") or "—", policy, str(count)],
                    f"{rule.get('expression', '')}\nTrigger: {rule.get('trigger') or 'writes to this expression'}",
                )
            )
        self._populate(self.rules_table, rows)
        self.watch_hint.setVisible(not rows)
        self._rule_selected()

    def _render_inspectors(self) -> None:
        snapshot = self._snapshot if self._snapshot.get("state") in {"running", "stopped"} else {}
        threads = []
        for thread in snapshot.get("threads", []):
            frame = thread.get("frame") or {}
            threads.append(
                (
                    str(thread.get("id")),
                    [
                        str(thread.get("id", "")),
                        thread.get("state", ""),
                        str(frame.get("func") or thread.get("target-id", "")),
                    ],
                    str(thread),
                )
            )
        self._populate(self.threads_table, threads)
        self._populate(
            self.frames_table,
            [
                (
                    int(frame.get("level", i)),
                    [str(frame.get("level", i)), frame.get("func", "?"), self._hex(frame.get("addr"))],
                    f"{frame.get('file', '')}:{frame.get('line', '')}",
                )
                for i, frame in enumerate(snapshot.get("frames", []))
            ],
        )
        self._populate(
            self.registers_table,
            [
                (register.get("name"), [register.get("name", ""), str(register.get("value", ""))], "")
                for register in snapshot.get("registers", [])
            ],
        )
        self._populate(
            self.modules_table,
            [
                (
                    module["id"],
                    [
                        str(module.get("path", "")).rsplit("/", 1)[-1],
                        self._hex(module.get("start")),
                        self._hex(module.get("end")),
                        self._hex(module.get("load_bias")),
                    ],
                    (
                        f"{module.get('path', '')}\nLinked base: {self._hex(module.get('linked_base'))}"
                        f"\n{module.get('ranges', '')}"
                    ),
                )
                for module in snapshot.get("modules", [])
            ],
        )

        self._filter_table(self.registers_table, self.register_filter.text())
        self._filter_table(self.modules_table, self.module_filter.text())
        self.module_warning.setText(snapshot.get("mapping_error") or "")
        self.module_warning.setVisible(bool(snapshot.get("mapping_error")))
        self._populate(
            self.mappings_table,
            [
                (
                    # QVariant integer storage is signed; kernel/vsyscall
                    # mappings can occupy the upper half of a 64-bit address.
                    self._hex(mapping["start"]),
                    [
                        self._hex(mapping["start"]),
                        self._hex(mapping["end"]),
                        mapping.get("permissions", ""),
                        mapping.get("path") or "Anonymous",
                    ],
                    str(mapping),
                )
                for mapping in snapshot.get("memory_maps", [])
            ],
        )
        self._filter_table(self.mappings_table, self.mapping_filter.text())

    @staticmethod
    def _filter_table(table: QTableWidget, text: str) -> None:
        needle = text.casefold()
        for row in range(table.rowCount()):
            haystack = " ".join(
                item.text() for col in range(table.columnCount()) if (item := table.item(row, col)) is not None
            ).casefold()
            table.setRowHidden(row, needle not in haystack)

    def _render_activity(self) -> None:
        events = []
        for index, event in enumerate(self._snapshot.get("events", [])):
            if isinstance(event, dict):
                timestamp = event.get("timestamp", event.get("time", ""))
                stamp = (
                    datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
                    if isinstance(timestamp, (int, float))
                    else str(timestamp)
                )
                kind = str(event.get("event", event.get("type", event.get("kind", ""))))
                message = str(event.get("message", event.get("value", event)))
                if kind == "sample":
                    message = f"{event.get('label', event.get('rule_id', 'Variable'))}: {event.get('value', '')}"
            else:
                stamp, kind, message = "", "", str(event)
            events.append((index, [stamp, kind, message], message))
        self._populate(self.events_table, events)
        self._populate(
            self.breakpoints_table,
            [
                (
                    str(bp.get("number", "")),
                    [
                        str(bp.get("number", "")),
                        str(bp.get("enabled", "")),
                        str(bp.get("type", bp.get("kind", ""))),
                        str(bp.get("original-location", bp.get("what", bp.get("addr", "")))),
                        str(bp.get("cond", bp.get("condition", ""))),
                    ],
                    str(bp),
                )
                for bp in self._snapshot.get("breakpoints", [])
            ],
        )
        output = self._snapshot.get("output") or []
        text = "".join(str(line.get("text", line)) if isinstance(line, dict) else str(line) for line in output)
        # The program's PTY can emit ANSI colors/cursor commands. This pane is a
        # text log; retain the raw stream in the service and render readable text.
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).replace("\r\n", "\n")
        if text != self.console_output.toPlainText():
            scrollbar = self.console_output.verticalScrollBar()
            at_end = scrollbar.value() == scrollbar.maximum()
            self.console_output.setPlainText(text)
            if at_end:
                scrollbar.setValue(scrollbar.maximum())

    def _update_controls(self) -> None:
        state = self._snapshot.get("state", "disconnected")
        stopped = state == "stopped" and not self._busy
        for control in self._stopped_controls:
            control.setEnabled(stopped)
        self.connect_button.setEnabled(state in {"disconnected", "ready", "exited", "error"} and not self._busy)
        self.pause_button.setEnabled(state == "running" and not self._busy)
        active = state in {"running", "stopped"}
        self.stop_button.setEnabled(active and not self._busy)
        self.detach_button.setEnabled(active and not self._busy)
        self.refresh_button.setEnabled(stopped)
        target_input = active and self._snapshot.get("capabilities", {}).get("input", False) and not self._busy
        self.target_input.setEnabled(target_input)
        self.target_send_button.setEnabled(target_input)
        self.target_newline.setEnabled(target_input)
        rule = self._selected_rule()
        self.toggle_rule_button.setEnabled(stopped and rule is not None)
        self.remove_rule_button.setEnabled(stopped and rule is not None)
        self.edit_rule_button.setEnabled(stopped and rule is not None and rule.get("mode") in {"clamp", "custom"})

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.show()

    @staticmethod
    def _context(snapshot: dict) -> dict:
        frame = snapshot.get("frame") or {}
        return {
            "expected_thread": snapshot.get("selected_thread"),
            "expected_frame": int(frame["level"]) if frame.get("level") is not None else None,
        }

    def _connect(self) -> None:
        project = self.instance.project.am_obj
        executable = project.filename if project is not None else ""
        initial = self.runtime.snapshot()
        dialog = RuntimeConnectionDialog(executable, self._snapshot.get("gdb_path", "gdb"), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            method, kwargs = dialog.configuration()
            path = dialog.gdb_path.text().strip()

            def connect():
                if self.runtime.snapshot().get("state") != "disconnected":
                    self.runtime.close()
                self.runtime.configure_gdb(path)
                return getattr(self.runtime, method)(**kwargs)

            self._call(
                lambda: self.runtime.checked(
                    connect, initial.get("generation", 0), states={initial.get("state", "disconnected")}
                ),
                "connecting",
            )

    def open_binding(
        self,
        expression: str = "",
        label: str = "",
        mode: str = "monitor",
        trigger: str | None = None,
        note: str = "",
        expected_generation: int | None = None,
    ) -> None:
        """Open a reviewable variable action, including bindings selected in pseudocode."""
        snapshot = self.runtime.snapshot()
        if snapshot.get("state") != "stopped":
            self._show_error("Connect and pause the target before adding a runtime variable.")
            return
        generation = snapshot.get("generation", 0)
        if expected_generation is not None and expected_generation != generation:
            self._show_error("The runtime session changed while resolving this variable. Select it again.")
            return
        dialog = RuntimeRuleDialog(self.runtime, expression, label, mode, trigger, note, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        config = dialog.configuration()
        if config["mode"] == "set":
            location = re.fullmatch(r"\*(0x[0-9a-fA-F]+)", config["trigger"] or "")
            pc = int(location.group(1), 0) if location is not None else (snapshot.get("frame") or {}).get("addr")
            self.submit(
                "execute_console",
                f"set variable {config['expression']} = {config['value']}",
                expected_generation=generation,
                expected_pc=pc,
                **self._context(snapshot),
            )
        else:
            context = self._context(snapshot) if not config["trigger"] else {}
            self.submit("add_rule", expected_generation=generation, **context, **config)

    def resolve_binding(self, resolver: Callable[[GDBRuntime], dict], mode: str = "monitor") -> None:
        generation = self.runtime.snapshot().get("generation", 0)
        self._call(
            lambda: self.runtime.checked(lambda: resolver(self.runtime), generation),
            "resolving live variable",
            lambda binding: self.open_binding(**binding, mode=mode, expected_generation=generation),
        )

    def _selected_rule(self) -> dict | None:
        key = self._selected_id(self.rules_table)
        return next((rule for rule in self._snapshot.get("rules", []) if rule["id"] == key), None)

    def _rule_selected(self) -> None:
        rule = self._selected_rule()
        if rule is not None:
            script = rule.get("generated_script") or []
            self.rule_preview.setPlainText(script if isinstance(script, str) else "\n".join(script))
            self.toggle_rule_button.setText("Disable" if rule.get("enabled", True) else "Enable")
            self.edit_rule_button.setText("Edit hook…" if rule.get("mode") == "custom" else "Change value…")
            samples = rule.get("samples") or []
            self.chart.set_samples(samples if isinstance(samples, list) else [], rule.get("label", ""))
        else:
            self.rule_preview.clear()
            self.chart.set_samples([], "Select a variable to see its recent values")
        self._update_controls()

    def _toggle_rule(self) -> None:
        rule = self._selected_rule()
        if rule:
            self.submit("update_rule", rule["id"], enabled=not rule.get("enabled", True))

    def _edit_rule(self, *_args) -> None:
        rule = self._selected_rule()
        if not rule or rule.get("mode") not in {"clamp", "custom"} or self._snapshot.get("state") != "stopped":
            return
        generation = self.runtime.snapshot().get("generation", 0)
        if rule["mode"] == "custom":
            dialog = RuntimeRuleDialog(
                self.runtime,
                rule["expression"],
                rule["label"],
                "custom",
                rule.get("trigger"),
                "Edit the commands for this hook. Its binding, breakpoint, and history are preserved.",
                self,
            )
            dialog.lock_binding()
            commands = rule.get("commands") or []
            dialog.commands.setPlainText(commands if isinstance(commands, str) else "\n".join(commands))
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.submit(
                    "update_rule",
                    rule["id"],
                    commands=dialog.configuration()["commands"],
                    expected_generation=generation,
                )
            return
        value, accepted = QInputDialog.getText(
            self, "Change clamp value", "New GDB value", text=str(rule.get("value", ""))
        )
        if accepted and value.strip():
            self.submit("update_rule", rule["id"], value=value.strip(), expected_generation=generation)

    def _remove_rule(self) -> None:
        rule = self._selected_rule()
        if rule:
            self.submit("remove_rule", rule["id"])

    def _copy_rule(self) -> None:
        QApplication.clipboard().setText(self.rule_preview.toPlainText())

    def _select_thread(self, row: int, _column: int) -> None:
        item = self.threads_table.item(row, 0)
        if self._snapshot.get("state") == "stopped" and item is not None:
            self.submit("select_thread", str(item.data(Qt.ItemDataRole.UserRole)))

    def _select_frame(self, row: int, _column: int) -> None:
        item = self.frames_table.item(row, 0)
        if self._snapshot.get("state") == "stopped" and item is not None:
            self.submit("select_frame", item.data(Qt.ItemDataRole.UserRole))

    def _edit_register(self, row: int, _column: int) -> None:
        if self._snapshot.get("state") != "stopped":
            return
        snapshot = self.runtime.snapshot()
        generation = snapshot.get("generation", 0)
        name_item, value_item = self.registers_table.item(row, 0), self.registers_table.item(row, 1)
        if name_item is None or value_item is None:
            return
        name = name_item.text()
        value, accepted = QInputDialog.getText(self, f"Write {name}", "New GDB value", text=value_item.text())
        if accepted and value.strip():
            self.submit(
                "write_register",
                name,
                value.strip(),
                expected_generation=generation,
                expected_pc=(snapshot.get("frame") or {}).get("addr"),
                **self._context(snapshot),
            )

    def _static_base(self) -> int:
        project = self.instance.project.am_obj
        if project is None:
            raise ValueError("Open the target binary in angr-management before mapping analysis addresses.")
        return project.loader.main_object.mapped_base

    def _show_pc(self) -> None:
        frame = self._snapshot.get("frame") or {}
        address = frame.get("addr")
        if address is None:
            self._show_error("The stopped frame has no program counter.")
            return
        try:
            base = self._static_base()
        except ValueError as exc:
            self._show_error(str(exc))
            return
        project = self.instance.project.am_obj
        if project is None:
            return
        module = project.loader.main_object
        generation = self.runtime.snapshot().get("generation", 0)

        def map_pc():
            verify_module_identity(self.runtime, module.binary, getattr(module, "build_id", None))
            return self.runtime.runtime_to_static(int(address, 0) if isinstance(address, str) else address, base)

        self._call(lambda: self.runtime.checked(map_pc, generation), "mapping program counter", self.workspace.jump_to)

    def _map_address(self) -> None:
        try:
            address = int(self.static_address.text().strip(), 0)
            text = self.module_static_base.text().strip()
            base = int(text, 0) if text else self._static_base()
        except ValueError as exc:
            self._show_error(str(exc))
            return
        module = self._selected_id(self.modules_table)
        if module is not None and not self.module_static_base.text().strip():
            self._show_error(
                "Enter the selected module's analysis base, or clear the module selection to map the main binary."
            )
            return
        self.submit(
            "static_to_runtime",
            address,
            base,
            module_id=module,
            on_result=lambda mapped: self.mapping_label.setText(f"Analysis {address:#x} → runtime {mapped:#x}"),
        )

    @staticmethod
    def _resolve_address(runtime: GDBRuntime, expression: str) -> int:
        try:
            return int(expression, 0)
        except ValueError:
            result = runtime.evaluate(expression)
            match = re.match(r"\s*(0x[0-9a-fA-F]+|[0-9]+)(?:\s|$)", result)
            if match is None:
                raise ValueError(f"The expression did not evaluate to an address: {result}") from None
            return int(match.group(1), 0)

    def _read_memory(self) -> None:
        expression = self.memory_address.text().strip()
        size = self.memory_size.value()
        generation = self.runtime.snapshot().get("generation", 0)

        def read():
            address = self._resolve_address(self.runtime, expression)
            return address, self.runtime.read_memory(address, size)

        self._call(lambda: self.runtime.checked(read, generation), "reading memory", self._display_memory)

    def _open_mapping(self, row: int, _column: int) -> None:
        if self._snapshot.get("state") != "stopped":
            return
        item = self.mappings_table.item(row, 0)
        if item is None:
            return
        address = int(item.data(Qt.ItemDataRole.UserRole), 0)
        mapping = next(item for item in self._snapshot.get("memory_maps", []) if item["start"] == address)
        if "r" not in mapping.get("permissions", ""):
            self._show_error("This mapped range is not readable.")
            return
        self.memory_address.setText(f"{address:#x}")
        self.memory_size.setValue(min(256, mapping["end"] - address))
        self.inspectors.setCurrentWidget(self.memory_panel)
        self._read_memory()

    def _display_memory(self, result: tuple[int, bytes]) -> None:
        address, data = result
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset : offset + 16]
            hexbytes = " ".join(f"{byte:02x}" for byte in chunk)
            ascii_bytes = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            lines.append(f"{address + offset:016x}  {hexbytes:<47}  {ascii_bytes}")
        self.memory_text.setPlainText("\n".join(lines))

    def _write_memory(self) -> None:
        snapshot = self.runtime.snapshot()
        generation = snapshot.get("generation", 0)
        value, accepted = QInputDialog.getText(
            self, "Write live memory", "Hex bytes to write at the address above, e.g. 64 00 00 00"
        )
        if not accepted:
            return
        try:
            data = bytes.fromhex(value)
            if not data:
                raise ValueError("Enter at least one byte.")
        except ValueError as exc:
            self._show_error(str(exc))
            return
        expression = self.memory_address.text().strip()

        def write():
            address = self._resolve_address(self.runtime, expression)
            self.runtime.write_memory(address, data)
            return address, self.runtime.read_memory(address, len(data))

        frame = snapshot.get("frame") or {}
        self._call(
            lambda: self.runtime.checked(
                write,
                generation,
                frame.get("addr"),
                thread_id=snapshot.get("selected_thread"),
                frame_level=int(frame["level"]) if frame.get("level") is not None else None,
            ),
            "writing memory",
            self._display_memory,
        )

    def _add_breakpoint(self) -> None:
        generation = self.runtime.snapshot().get("generation", 0)
        dialog = RuntimeBreakpointDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.submit("add_breakpoint", expected_generation=generation, **dialog.configuration())

    def _toggle_breakpoint(self) -> None:
        number = self._selected_id(self.breakpoints_table)
        bp = next((bp for bp in self._snapshot.get("breakpoints", []) if str(bp.get("number")) == number), None)
        if bp:
            self.submit("enable_breakpoint", number, enabled=bp.get("enabled") not in {True, "y", "1"})

    def _remove_breakpoint(self) -> None:
        number = self._selected_id(self.breakpoints_table)
        if number is not None:
            self.submit("remove_breakpoint", number)

    def _console_command(self) -> None:
        command = self.console_input.text().strip()
        if command:
            self.console_input.clear()
            self.submit("execute_console", command)

    def _console_script(self) -> None:
        snapshot = self.runtime.snapshot()
        generation = snapshot.get("generation", 0)
        script, accepted = QInputDialog.getMultiLineText(self, "Run GDB script", "GDB commands to run in this session")
        if accepted and script.strip():
            self.submit(
                "execute_console",
                script,
                expected_generation=generation,
                expected_pc=(snapshot.get("frame") or {}).get("addr"),
                **self._context(snapshot),
            )

    def _send_input(self) -> None:
        text = self.target_input.text()
        if self.target_newline.isChecked():
            text += "\n"
        if text:
            self.target_input.clear()
            self.submit("send_input", text)

    def shutdown(self, *, wait: bool = False) -> None:
        """Cancel queued work before application shutdown or view destruction."""
        if self._closed:
            if wait:
                self._executor.shutdown(wait=True, cancel_futures=True)
            return
        self._closed = True
        self._render_timer.stop()
        self._unsubscribe()
        self._executor.shutdown(wait=wait, cancel_futures=True)

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.PaletteChange and hasattr(self, "footer"):
            self.refresh()

    def closeEvent(self, event) -> None:
        self.shutdown()
        super().closeEvent(event)
