from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from angr import sim_options as so
from pyqodeng.core.api import CodeEdit
from pyqodeng.core.modes import AutoIndentMode, PygmentsSyntaxHighlighter
from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt
from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from angrmanagement.data.jobs import FuzzerJob
from angrmanagement.ui.widgets.qfunction_combobox import QFunctionComboBox

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


@dataclass
class FuzzerConfig:
    name: str
    target_function: str = ""
    entry_point: int = 0
    input_type: str = "symbolic"  # symbolic, file, network
    input_size: int = 100
    timeout: int = 60
    max_iterations: int = 1000
    apply_fn_code: str = ""
    notes: str = ""
    work_folder: str = ""  # Path to work folder for on-disk corpus, empty = temp dir

    @staticmethod
    def default(name: str) -> FuzzerConfig:
        default_apply_fn = '''def apply_fn(state: angr.SimState, input_bytes: bytes) -> None:
    """Apply the fuzzer input to the state.

    Example:
        state.regs.r0 = SRAM_BASE + 0x1000  # Input buffer address
        state.regs.r1 = len(input_bytes)    # Length
        state.memory.store(state.regs.r0, input_bytes)
    """
    pass
'''
        return FuzzerConfig(name=name, apply_fn_code=default_apply_fn)


class FuzzerConfigListModel(QAbstractListModel):
    """Model for the list of fuzzer configurations."""

    def __init__(self, configs: list[FuzzerConfig] | None = None) -> None:
        super().__init__()
        self._configs = configs if configs is not None else []

    def rowCount(self, parent: QModelIndex | None = None) -> int:
        if parent is None:
            parent = QModelIndex()
        return len(self._configs)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._configs):
            return None

        config = self._configs[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return config.name
        elif role == Qt.ItemDataRole.UserRole:
            return config

        return None

    def add_config(self, config: FuzzerConfig) -> None:
        """Add a new config to the model."""
        self.beginInsertRows(QModelIndex(), len(self._configs), len(self._configs))
        self._configs.append(config)
        self.endInsertRows()

    def remove_config(self, index: int) -> None:
        """Remove a config from the model."""
        if 0 <= index < len(self._configs):
            self.beginRemoveRows(QModelIndex(), index, index)
            del self._configs[index]
            self.endRemoveRows()

    def get_config(self, index: int) -> FuzzerConfig | None:
        """Get config at index."""
        if 0 <= index < len(self._configs):
            return self._configs[index]
        return None

    def update_config(self, index: int, config: FuzzerConfig) -> None:
        """Update config at index."""
        if 0 <= index < len(self._configs):
            self._configs[index] = config
            model_index = self.index(index, 0)
            self.dataChanged.emit(model_index, model_index)


class FuzzerView(InstanceView):
    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("fuzzer", workspace, default_docking_position, instance)
        self.base_caption = "Fuzz Config"

        self._config_model = FuzzerConfigListModel([FuzzerConfig.default("New Fuzz Test 1")])
        self._current_config: FuzzerConfig | None = None
        self._current_config_index: int = -1

        self._init_widgets()
        self._update_function_list()

        # Select the first config by default
        if self._config_model.rowCount() > 0:
            self._config_list.setCurrentIndex(self._config_model.index(0, 0))
            self._on_config_selected(self._config_model.index(0, 0))

    #
    # Public methods
    #

    def reload(self) -> None:
        self._update_function_list()

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        """Initialize the UI widgets."""
        main_layout = QHBoxLayout()

        # Main content area (left side)
        content_widget = self._init_content_area()

        # Config list panel (right side)
        config_panel = self._init_config_panel()

        # Use a splitter to allow resizing
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(content_widget)
        splitter.addWidget(config_panel)
        splitter.setStretchFactor(0, 3)  # Content area takes 75% of space
        splitter.setStretchFactor(1, 1)  # Config panel takes 25% of space

        main_layout.addWidget(splitter)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    def _init_content_area(self) -> QWidget:
        """Initialize the main content area showing the editable fuzzer config."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Title and Run button
        title_layout = QHBoxLayout()
        self._config_name_label = QLabel("No configuration selected")
        font = self._config_name_label.font()
        font.setPointSize(font.pointSize() + 2)
        font.setBold(True)
        self._config_name_label.setFont(font)
        title_layout.addWidget(self._config_name_label)
        title_layout.addStretch()

        self._run_btn = QPushButton("Run Fuzzer")
        self._run_btn.clicked.connect(self._on_run_fuzzer)
        title_layout.addWidget(self._run_btn)

        layout.addLayout(title_layout)

        # Basic settings group
        basic_group = QGroupBox("Basic Settings")
        basic_layout = QVBoxLayout()

        # Name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self._name_edit = QLineEdit()
        self._name_edit.textChanged.connect(self._on_config_modified)
        name_layout.addWidget(self._name_edit)
        basic_layout.addLayout(name_layout)

        # Target function
        function_layout = QHBoxLayout()
        function_layout.addWidget(QLabel("Target Function:"))
        self._function_combo = QFunctionComboBox(
            show_all_functions=False,
            selection_callback=self._on_function_selected,
        )
        self._function_combo.functions = self.instance.kb.functions
        function_layout.addWidget(self._function_combo)
        basic_layout.addLayout(function_layout)

        # Entry point
        entry_layout = QHBoxLayout()
        entry_layout.addWidget(QLabel("Entry Point (hex):"))
        self._entry_edit = QLineEdit()
        self._entry_edit.setPlaceholderText("0x400000")
        self._entry_edit.textChanged.connect(self._on_config_modified)
        entry_layout.addWidget(self._entry_edit)
        basic_layout.addLayout(entry_layout)

        # Work folder
        work_folder_layout = QHBoxLayout()
        work_folder_layout.addWidget(QLabel("Work Folder:"))
        self._work_folder_edit = QLineEdit()
        self._work_folder_edit.setPlaceholderText("Leave empty for temp directory")
        self._work_folder_edit.textChanged.connect(self._on_config_modified)
        work_folder_layout.addWidget(self._work_folder_edit)

        self._work_folder_btn = QPushButton("Browse...")
        self._work_folder_btn.clicked.connect(self._on_browse_work_folder)
        work_folder_layout.addWidget(self._work_folder_btn)
        basic_layout.addLayout(work_folder_layout)

        basic_group.setLayout(basic_layout)
        layout.addWidget(basic_group)

        # Execution settings group
        exec_group = QGroupBox("Execution Settings")
        exec_layout = QVBoxLayout()

        # Timeout
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("Timeout (ms):"))
        self._timeout_edit = QLineEdit()
        self._timeout_edit.setPlaceholderText("10000")
        self._timeout_edit.textChanged.connect(self._on_config_modified)
        timeout_layout.addWidget(self._timeout_edit)
        exec_layout.addLayout(timeout_layout)

        # Max iterations
        iter_layout = QHBoxLayout()
        iter_layout.addWidget(QLabel("Max Iterations (0 = unlimited):"))
        self._max_iter_edit = QLineEdit()
        self._max_iter_edit.setPlaceholderText("0")
        self._max_iter_edit.textChanged.connect(self._on_config_modified)
        iter_layout.addWidget(self._max_iter_edit)
        exec_layout.addLayout(iter_layout)

        exec_group.setLayout(exec_layout)
        layout.addWidget(exec_group)

        # Apply function group
        apply_fn_group = QGroupBox("Apply Function")
        apply_fn_layout = QVBoxLayout()

        apply_fn_label = QLabel("Define the apply_fn to set up the state for each fuzzer input:")
        apply_fn_layout.addWidget(apply_fn_label)

        self._apply_fn_edit = CodeEdit()
        self._apply_fn_edit.use_spaces_instead_of_tabs = True
        self._apply_fn_edit.tab_length = 4
        self._apply_fn_edit.modes.append(PygmentsSyntaxHighlighter(self._apply_fn_edit.document()))
        self._apply_fn_edit.modes.append(AutoIndentMode())
        self._apply_fn_edit.setWordWrapMode(QTextOption.WrapMode.NoWrap)
        self._apply_fn_edit.setMinimumHeight(200)
        self._apply_fn_edit.textChanged.connect(self._on_config_modified)
        apply_fn_layout.addWidget(self._apply_fn_edit)

        apply_fn_group.setLayout(apply_fn_layout)
        layout.addWidget(apply_fn_group)

        # Notes group
        notes_group = QGroupBox("Notes")
        notes_layout = QVBoxLayout()
        self._notes_edit = QTextEdit()
        self._notes_edit.setPlaceholderText("Add notes about this fuzzer configuration...")
        self._notes_edit.setMaximumHeight(100)
        self._notes_edit.textChanged.connect(self._on_config_modified)
        notes_layout.addWidget(self._notes_edit)
        notes_group.setLayout(notes_layout)
        layout.addWidget(notes_group)

        widget.setLayout(layout)
        return widget

    def _init_config_panel(self) -> QWidget:
        """Initialize the config list panel on the right side."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Title
        title = QLabel("Fuzzer Configurations")
        font = title.font()
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        # Config list
        self._config_list = QListView()
        self._config_list.setModel(self._config_model)
        self._config_list.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._config_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._config_list.clicked.connect(self._on_config_selected)
        layout.addWidget(self._config_list)

        # Buttons
        button_layout = QHBoxLayout()

        self._create_btn = QPushButton("Create")
        self._create_btn.clicked.connect(self._on_create_config)
        button_layout.addWidget(self._create_btn)

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.clicked.connect(self._on_delete_config)
        button_layout.addWidget(self._delete_btn)

        layout.addLayout(button_layout)

        # Preset button with dropdown
        preset_layout = QHBoxLayout()
        self._preset_btn = QPushButton("Load Preset...")
        self._preset_btn.clicked.connect(self._on_load_preset)
        preset_layout.addWidget(self._preset_btn)
        layout.addLayout(preset_layout)

        widget.setLayout(layout)
        widget.setMaximumWidth(300)
        return widget

    def _update_function_list(self) -> None:
        """Update the function combobox with available functions."""
        if hasattr(self, "_function_combo"):
            self._function_combo.functions = self.instance.kb.functions
            self._function_combo.reload()

    def _load_config_to_ui(self, config: FuzzerConfig) -> None:
        """Load a config into the UI widgets."""
        self._current_config = config

        # Block signals while updating to avoid triggering modifications
        self._name_edit.blockSignals(True)
        self._entry_edit.blockSignals(True)
        self._work_folder_edit.blockSignals(True)
        self._timeout_edit.blockSignals(True)
        self._max_iter_edit.blockSignals(True)
        self._apply_fn_edit.blockSignals(True)
        self._notes_edit.blockSignals(True)

        self._config_name_label.setText(f"Configuration: {config.name}")
        self._name_edit.setText(config.name)
        self._entry_edit.setText(hex(config.entry_point) if config.entry_point else "")
        self._work_folder_edit.setText(config.work_folder)
        self._timeout_edit.setText(str(config.timeout))
        self._max_iter_edit.setText(str(config.max_iterations))
        self._apply_fn_edit.setPlainText(config.apply_fn_code, mime_type="text/x-python", encoding="utf-8")
        self._notes_edit.setPlainText(config.notes)

        # Set function if available
        if config.target_function:
            self._function_combo.blockSignals(True)
            self._function_combo.setCurrentText(config.target_function)
            self._function_combo.blockSignals(False)

        # Re-enable signals
        self._name_edit.blockSignals(False)
        self._entry_edit.blockSignals(False)
        self._work_folder_edit.blockSignals(False)
        self._timeout_edit.blockSignals(False)
        self._max_iter_edit.blockSignals(False)
        self._apply_fn_edit.blockSignals(False)
        self._notes_edit.blockSignals(False)

    def _save_config_from_ui(self) -> None:
        """Save the current UI state back to the config."""
        if self._current_config is None or self._current_config_index == -1:
            return

        # Parse entry point
        entry_point = 0
        entry_text = self._entry_edit.text().strip()
        if entry_text:
            try:
                entry_point = int(entry_text, 16 if entry_text.startswith("0x") else 10)
            except ValueError:
                entry_point = 0

        # Parse numeric values
        try:
            timeout = int(self._timeout_edit.text())
        except ValueError:
            timeout = 10000

        try:
            max_iterations = int(self._max_iter_edit.text())
        except ValueError:
            max_iterations = 0

        # Update config
        updated_config = FuzzerConfig(
            name=self._name_edit.text(),
            target_function=self._function_combo.currentText() or "",
            entry_point=entry_point,
            input_type="symbolic",
            input_size=100,
            timeout=timeout,
            max_iterations=max_iterations,
            apply_fn_code=self._apply_fn_edit.toPlainText(),
            notes=self._notes_edit.toPlainText(),
            work_folder=self._work_folder_edit.text(),
        )

        self._current_config = updated_config
        self._config_model.update_config(self._current_config_index, updated_config)
        self._config_name_label.setText(f"Configuration: {updated_config.name}")

    #
    # Event handlers
    #

    def _on_config_selected(self, index: QModelIndex) -> None:
        """Handle config selection from the list."""
        if not index.isValid():
            return

        # Save current config before switching
        if self._current_config_index != -1:
            self._save_config_from_ui()

        config = self._config_model.get_config(index.row())
        if config:
            self._current_config_index = index.row()
            self._load_config_to_ui(config)

    def _on_create_config(self) -> None:
        """Create a new fuzzer config with auto-generated name."""
        # Find next available number
        existing_names = set()
        for i in range(self._config_model.rowCount()):
            config = self._config_model.get_config(i)
            if config:
                existing_names.add(config.name)

        # Generate unique name
        counter = 1
        while True:
            name = f"New Fuzz Test {counter}"
            if name not in existing_names:
                break
            counter += 1

        new_config = FuzzerConfig.default(name)
        self._config_model.add_config(new_config)

        # Select the new config
        new_index = self._config_model.rowCount() - 1
        self._config_list.setCurrentIndex(self._config_model.index(new_index, 0))
        self._on_config_selected(self._config_model.index(new_index, 0))

    def _on_delete_config(self) -> None:
        """Delete the currently selected config."""
        current_index = self._config_list.currentIndex()
        if not current_index.isValid():
            QMessageBox.warning(self, "No Selection", "Please select a configuration to delete.")
            return

        # Don't allow deleting the last config
        if self._config_model.rowCount() <= 1:
            QMessageBox.warning(self, "Cannot Delete", "Cannot delete the last configuration.")
            return

        config = self._config_model.get_config(current_index.row())
        reply = QMessageBox.question(
            self,
            "Delete Configuration",
            f"Are you sure you want to delete '{config.name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self._config_model.remove_config(current_index.row())

            # Select another config
            if self._config_model.rowCount() > 0:
                new_index = min(current_index.row(), self._config_model.rowCount() - 1)
                self._config_list.setCurrentIndex(self._config_model.index(new_index, 0))
                self._current_config_index = -1
                self._on_config_selected(self._config_model.index(new_index, 0))
            else:
                self._current_config = None
                self._current_config_index = -1

    def _on_config_modified(self) -> None:
        """Handle any modification to the config fields."""
        # Auto-save when fields are modified
        if self._current_config_index != -1:
            self._save_config_from_ui()

    def _on_function_selected(self, function) -> None:
        """Handle function selection change."""
        if self._current_config_index != -1:
            self._save_config_from_ui()

    def _on_browse_work_folder(self) -> None:
        """Handle browse button click for work folder selection."""
        current_path = self._work_folder_edit.text() or ""
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Work Folder",
            current_path,
            QFileDialog.Option.ShowDirsOnly
        )
        if folder:
            self._work_folder_edit.setText(folder)

    def _on_load_preset(self) -> None:
        """Show menu to load a preset configuration."""
        menu = QMenu(self)

        # Add preset options
        stm32_action = menu.addAction("STM32 Firmware Parser")
        uart_action = menu.addAction("UART Task Handler (A5 Protocol)")

        # Show menu at button position
        action = menu.exec(self._preset_btn.mapToGlobal(self._preset_btn.rect().bottomLeft()))

        if action == stm32_action:
            self._load_stm32_preset()
        elif action == uart_action:
            self._load_uart_preset()

    def _load_stm32_preset(self) -> None:
        """Load the STM32 firmware parser preset from parse.py."""
        apply_fn_code = '''def apply_fn(state, input_bytes: bytes) -> None:
    """Apply function for STM32 firmware packet parser.

    Based on packet_parse_data_block function:
    [Message Type][Session ID][Anti-byte][Payload Data][CRC16]
       1 byte       1 byte      1 byte     N bytes     2 bytes
    """
    import claripy

    SRAM_BASE = 0x20000000

    # Set up function arguments (ARM calling convention)
    state.regs.r0 = SRAM_BASE + 0x1000  # Input buffer address
    state.regs.r1 = len(input_bytes)    # Packet length
    state.regs.r2 = SRAM_BASE + 0x2000  # Output buffer address
    state.regs.r3 = SRAM_BASE + 0x3000  # Output length pointer

    # Store input data in memory
    state.memory.store(state.regs.r0, input_bytes)
    state.memory.store(state.regs.r2, claripy.BVV(b"\\x00" * 256))
    state.memory.store(state.regs.r3, claripy.BVV(0, 32))

    # Set session_id on stack (5th argument)
    state.memory.store(state.regs.sp - 4, claripy.BVV(0x42, 32))
    state.regs.sp -= 4
    state.regs.lr = 0xDDDD0001
    state.memory.map_region(0xDDDD0000, 0x1000, 7)
'''

        notes = (
            "Fuzzer for STM32 firmware packet parser. Targets packet_parse_data_block function.\n\n"
            "Packet format: [Type][SessionID][Anti-byte][Payload][CRC16]\n"
            "Entry point: 0x08006038\nFlash base: 0x08000000\nSRAM base: 0x20000000"
        )

        preset_config = FuzzerConfig(
            name="STM32 Firmware Parser",
            target_function="packet_parse_data_block",
            entry_point=0x08006038,
            timeout=10000,
            max_iterations=0,
            apply_fn_code=apply_fn_code,
            notes=notes,
        )

        self._config_model.add_config(preset_config)
        new_index = self._config_model.rowCount() - 1
        self._config_list.setCurrentIndex(self._config_model.index(new_index, 0))
        self._on_config_selected(self._config_model.index(new_index, 0))

    def _load_uart_preset(self) -> None:
        """Load the UART task handler preset for A5 protocol processing."""
        apply_fn_code = '''def apply_fn(state, input_bytes: bytes) -> None:
    """Apply function for UART task handler A5 protocol.

    Targets the UART task handler function that processes A5 protocol commands.
    Supported commands: 0x31 (49), 0xC1 (193), 0xA4 (164), 0x52 (82), 0x60 (96)
    """
    import claripy

    SRAM_BASE = 0x20000000

    # Set up function arguments (ARM calling convention)
    state.regs.r0 = SRAM_BASE + 0x1000  # Input buffer address

    # Store input data in memory
    state.memory.store(state.regs.r0, input_bytes)

    # Handle partial packets (pad if less than 2 bytes)
    if len(input_bytes) < 2:
        padded = input_bytes + b"\\x00" * (2 - len(input_bytes))
        state.memory.store(state.regs.r0, padded)

    # Set up memory locations used by the function
    state.memory.store(0x20002BF8, claripy.BVV(0, 32))
    state.memory.store(0x20002C00, claripy.BVV(0, 32))
    state.memory.store(0x20002C04, claripy.BVV(0, 32))
    state.memory.store(0x20002C08, claripy.BVV(0, 32))
    state.memory.store(0x20002C0C, claripy.BVV(0, 32))

    # Set return address
    state.regs.lr = 0xDDDD0001
    state.memory.map_region(0xDDDD0000, 0x1000, 7)
'''

        notes = (
            "Fuzzer for UART task handler A5 protocol processing.\n\n"
            "Supported commands:\n"
            "- 0x31 (49): CMD_49\n"
            "- 0xC1 (193): CMD_193 with 19-byte data\n"
            "- 0xA4 (164): CMD_164 with 14-byte data\n"
            "- 0x52 (82): CMD_82\n"
            "- 0x60 (96): CMD_96\n\n"
            "Entry point: 0x0800C188\n"
            "Flash base: 0x08000000\n"
            "SRAM base: 0x20000000"
        )

        preset_config = FuzzerConfig(
            name="UART Task Handler (A5 Protocol)",
            target_function="uart_task_handler",
            entry_point=0x0800C188,
            timeout=10000,
            max_iterations=0,
            apply_fn_code=apply_fn_code,
            notes=notes,
        )

        self._config_model.add_config(preset_config)
        new_index = self._config_model.rowCount() - 1
        self._config_list.setCurrentIndex(self._config_model.index(new_index, 0))
        self._on_config_selected(self._config_model.index(new_index, 0))

    def _on_run_fuzzer(self) -> None:
        """Run the fuzzer with the current configuration."""
        if self._current_config is None:
            QMessageBox.warning(self, "No Configuration", "Please select a configuration to run.")
            return

        # Save current config first
        self._save_config_from_ui()

        try:
            # Get the apply_fn code
            apply_fn_code = self._current_config.apply_fn_code.strip()
            if not apply_fn_code:
                QMessageBox.warning(self, "Error", "apply_fn code is empty.")
                return

            # Validate the apply_fn code can be executed
            try:
                namespace = {
                    "angr": __import__("angr"),
                    "claripy": __import__("claripy"),
                }
                exec(apply_fn_code, namespace)
                apply_fn = namespace.get("apply_fn")

                if not apply_fn or not callable(apply_fn):
                    QMessageBox.warning(self, "Error", "apply_fn is not defined or not callable.")
                    return
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Error validating apply_fn code: {e}")
                return

            # Create a base state
            entry_point = self._current_config.entry_point or self.instance.project.entry
            base_state = self.instance.project.factory.blank_state(
                addr=entry_point, add_options={so.ZERO_FILL_UNCONSTRAINED_MEMORY, so.ZERO_FILL_UNCONSTRAINED_REGISTERS}
            )

            # Create fuzzer job
            max_iter = self._current_config.max_iterations if self._current_config.max_iterations > 0 else None

            # Open the fuzzer results view immediately
            results_view = self._get_or_create_fuzzer_results_view()

            def on_finish(result):
                """Callback when fuzzer job completes."""
                self._on_fuzzer_finished(result)

            job = FuzzerJob.create(
                instance=self.instance,
                base_state=base_state,
                apply_fn_code=apply_fn_code,
                timeout=self._current_config.timeout,
                max_iterations=max_iter,
                work_folder=self._current_config.work_folder,
                on_finish=on_finish,
            )

            # Set the active fuzzer job in results view
            results_view.set_active_fuzzer_job(job)

            # Connect job progress to results view
            def on_job_progress(j, percentage, text):
                if j == job:
                    results_view.update_progress_from_job(text)

            self.workspace.job_manager.job_progressed.connect(on_job_progress)

            # Add job to job manager
            self.workspace.job_manager.add_job(job)

            QMessageBox.information(
                self,
                "Fuzzer Started",
                f"Fuzzer job submitted (max iterations: {max_iter or 'unlimited'}).\n"
                f"Check the Fuzzer Results view for progress.",
            )

        except ImportError as e:
            QMessageBox.critical(self, "Error", f"Could not import fuzzer module: {e}")
        except Exception as e:
            import traceback

            QMessageBox.critical(self, "Error", f"Error preparing fuzzer: {e}\n\n{traceback.format_exc()}")

    def _on_fuzzer_finished(self, result: dict) -> None:
        """Handle fuzzer job completion and display results."""
        if result is None:
            return

        # Show results in the fuzzer results view
        self._show_fuzzer_results(result)

        # Show completion message
        QMessageBox.information(
            self,
            "Fuzzer Completed",
            f"Fuzzer completed!\n\n"
            f"Final corpus size: {result['final_corpus_size']}\n"
            f"Solutions found: {result['final_solutions_size']}\n\n"
            f"View detailed results in the Fuzzer Results view.",
        )

    def _get_or_create_fuzzer_results_view(self):
        """Get or create the fuzzer results view."""
        from angrmanagement.ui.views import FuzzerResultsView

        # Try to find existing fuzzer results view
        fuzzer_results_view = None
        for view in self.workspace.view_manager.views:
            if isinstance(view, FuzzerResultsView) and view.instance == self.instance:
                fuzzer_results_view = view
                break

        # Create new view if not found
        if fuzzer_results_view is None:
            fuzzer_results_view = FuzzerResultsView(self.workspace, "center", self.instance)
            self.workspace.add_view(fuzzer_results_view)

        # Bring the view to front and give it focus
        self.workspace.raise_view(fuzzer_results_view)
        fuzzer_results_view.setFocus()

        return fuzzer_results_view

    def _show_fuzzer_results(self, result: dict) -> None:
        """Show fuzzer results in the fuzzer results view."""
        fuzzer_results_view = self._get_or_create_fuzzer_results_view()

        # Update the view with final results
        fuzzer_results_view.update_results(result)
