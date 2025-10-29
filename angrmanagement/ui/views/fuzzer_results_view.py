from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .view import InstanceView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.workspace import Workspace


class CorpusTableModel(QAbstractTableModel):
    """Model for displaying corpus items."""

    def __init__(self, corpus_items: list[bytes] | None = None) -> None:
        super().__init__()
        self._corpus_items = corpus_items if corpus_items is not None else []

    def rowCount(self, parent: QModelIndex | None = None) -> int:
        if parent is None or not parent.isValid():
            return len(self._corpus_items)
        return 0

    def columnCount(self, parent: QModelIndex | None = None) -> int:
        if parent is None or not parent.isValid():
            return 3  # Index, Size, Preview
        return 0

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._corpus_items):
            return None

        item = self._corpus_items[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:  # Index
                return str(index.row())
            elif col == 1:  # Size
                return str(len(item))
            elif col == 2:  # Preview
                # Show hex preview for first 32 bytes
                preview = item[:32]
                hex_str = preview.hex()
                if len(item) > 32:
                    hex_str += "..."
                return hex_str

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        SECTIONS = ["Index", "Size", "Preview (hex)"]
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return SECTIONS[section]
        return None

    def set_corpus_items(self, items: list[bytes]) -> None:
        """Update the corpus items."""
        self.beginResetModel()
        self._corpus_items = items
        self.endResetModel()

    def get_item(self, row: int) -> bytes | None:
        """Get corpus item at row."""
        if 0 <= row < len(self._corpus_items):
            return self._corpus_items[row]
        return None


class FuzzerResultsView(InstanceView):
    """View for displaying fuzzer results including corpus, solutions, and statistics."""

    # Signal emitted when statistics should be updated
    statistics_updated = Signal(dict)

    def __init__(self, workspace: Workspace, default_docking_position: str, instance: Instance) -> None:
        super().__init__("fuzzer_results", workspace, default_docking_position, instance)

        self.base_caption = "Fuzzer Results"

        # Models
        self._corpus_model = CorpusTableModel()
        self._solutions_model = CorpusTableModel()

        # Statistics data
        self._stats_data: dict[str, Any] = {}
        self._worker_stats: dict[int, dict[str, Any]] = {}  # Track stats per worker

        # Timer for elapsed time
        self._start_time: float | None = None
        self._elapsed_timer = QTimer()
        self._elapsed_timer.timeout.connect(self._update_elapsed_time)

        # Reference to active fuzzer job
        self._active_fuzzer_job = None

        self._init_widgets()

    def reload(self) -> None:
        """Reload the view."""

    def set_active_fuzzer_job(self, job) -> None:
        """Set the active fuzzer job to query for corpus/solutions updates.

        Args:
            job: The FuzzerJob instance that is currently running
        """
        self._active_fuzzer_job = job

    def update_progress_from_job(self, progress_text: str, event_type: str = "") -> None:
        """Update the view with progress text from a job.

        Args:
            progress_text: Progress message like "Corpus: 10, Solutions: 2, Execs: 1000, Speed: 100/s, Coverage: 50/100"
            event_type: Type of event (e.g., "new_corpus", "new_objective")
        """
        import logging
        _l = logging.getLogger(__name__)

        # Start timer on first progress update
        if self._start_time is None:
            import time
            self._start_time = time.time()
            self._elapsed_timer.start(1000)  # Update every second

        # Parse the progress text
        stats = {}
        parsed_event_type = ""
        try:
            parts = progress_text.split(", ")
            for part in parts:
                if ": " in part:
                    key, value = part.split(": ", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    # Map keys to expected format
                    if key == "corpus":
                        stats["corpus_size"] = int(value)
                    elif key == "solutions":
                        stats["objective_size"] = int(value)
                    elif key == "execs":
                        stats["executions"] = int(value)
                    elif key == "speed":
                        stats["execs_per_sec"] = value
                    elif key == "coverage" and "/" in value:
                        # Parse "50/100" format
                        hit, total = value.split("/")
                        stats["edges_hit"] = int(hit)
                        stats["edges_total"] = int(total)
                    elif key == "event":
                        parsed_event_type = value
        except Exception:
            # If parsing fails, just show the raw text
            stats = {"raw_text": progress_text}

        # Update statistics display
        self._update_statistics(stats)

        # Update corpus and solutions from fuzzer on new entries
        actual_event = event_type or parsed_event_type
        _l.info(f"Event received: '{actual_event}' (from event_type='{event_type}', parsed='{parsed_event_type}')")

        # Always refresh on every update to keep corpus/solutions in sync
        # The fuzzer corpus/solutions grow over time, so we need to query periodically
        if self._active_fuzzer_job is not None:
            _l.info(f"Refreshing corpus/solutions (event: {actual_event})")
            self._refresh_corpus_and_solutions()

    def update_progress(self, update: dict[str, Any]) -> None:
        """Update the view with real-time progress from a worker.

        Args:
            update: Dictionary containing 'type', 'worker_id', 'stats', and 'fuzzer_type'
        """
        if update.get("type") != "progress":
            return

        worker_id = update.get("worker_id", 0)
        stats = update.get("stats", {})
        fuzzer_type = update.get("fuzzer_type", "")

        # Store worker-specific stats
        self._worker_stats[worker_id] = {
            "fuzzer_type": fuzzer_type,
            **stats,
        }

        # Aggregate statistics from all workers
        self._update_aggregated_statistics()

    def update_results(self, results: dict[str, Any]) -> None:
        """Update the view with fuzzer results."""
        # Update corpus from directory
        if "corpus_dir" in results:
            try:
                from angr.rustylib.fuzzer import OnDiskCorpus
                corpus = OnDiskCorpus(results["corpus_dir"])
                corpus_items = corpus.to_bytes_list()
                self._corpus_model.set_corpus_items(corpus_items)
                self._corpus_count_label.setText(f"Corpus ({len(corpus_items)} items)")
            except Exception as e:
                import logging
                logging.getLogger(__name__).error("Failed to load corpus from disk: %s", e)
        # Legacy: Update corpus from object
        elif "corpus" in results:
            corpus = results["corpus"]
            if hasattr(corpus, "to_bytes_list"):
                corpus_items = corpus.to_bytes_list()
            elif isinstance(corpus, list):
                corpus_items = corpus
            else:
                corpus_items = []
            self._corpus_model.set_corpus_items(corpus_items)
            self._corpus_count_label.setText(f"Corpus ({len(corpus_items)} items)")

        # Update solutions from directory
        if "solutions_dir" in results:
            try:
                from angr.rustylib.fuzzer import OnDiskCorpus
                solutions = OnDiskCorpus(results["solutions_dir"])
                solutions_items = solutions.to_bytes_list()
                self._solutions_model.set_corpus_items(solutions_items)
                self._solutions_count_label.setText(f"Solutions ({len(solutions_items)} items)")
            except Exception as e:
                import logging
                logging.getLogger(__name__).error("Failed to load solutions from disk: %s", e)
        # Legacy: Update solutions from object
        elif "solutions" in results:
            solutions = results["solutions"]
            if hasattr(solutions, "to_bytes_list"):
                solutions_items = solutions.to_bytes_list()
            elif isinstance(solutions, list):
                solutions_items = solutions
            else:
                solutions_items = []
            self._solutions_model.set_corpus_items(solutions_items)
            self._solutions_count_label.setText(f"Solutions ({len(solutions_items)} items)")

        # Update statistics
        self._update_statistics(results)

    def update_statistics(self, stats: dict[str, Any]) -> None:
        """Update only the statistics display."""
        self._update_statistics(stats)

    def _init_widgets(self) -> None:
        """Initialize the UI widgets."""
        main_layout = QVBoxLayout()

        # Create splitter for three sections
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Statistics section (top)
        stats_group = self._create_statistics_group()
        splitter.addWidget(stats_group)

        # Corpus section (middle)
        corpus_group = self._create_corpus_group()
        splitter.addWidget(corpus_group)

        # Solutions section (bottom)
        solutions_group = self._create_solutions_group()
        splitter.addWidget(solutions_group)

        # Set initial sizes (proportions)
        splitter.setStretchFactor(0, 1)  # Statistics: 25%
        splitter.setStretchFactor(1, 2)  # Corpus: 37.5%
        splitter.setStretchFactor(2, 2)  # Solutions: 37.5%

        main_layout.addWidget(splitter)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(main_layout)

    def _create_statistics_group(self) -> QWidget:
        """Create the statistics display group."""
        group = QGroupBox("Statistics")
        layout = QVBoxLayout()

        # Create a frame with grid layout for statistics
        stats_frame = QFrame()
        stats_frame.setFrameShape(QFrame.Shape.NoFrame)
        grid_layout = QGridLayout()
        grid_layout.setSpacing(10)
        grid_layout.setContentsMargins(10, 10, 10, 10)

        # Row 0: Elapsed Time
        elapsed_label = QLabel("Elapsed Time:")
        elapsed_label.setStyleSheet("font-weight: bold;")
        self._elapsed_value = QLabel("00:00:00")
        grid_layout.addWidget(elapsed_label, 0, 0, Qt.AlignmentFlag.AlignRight)
        grid_layout.addWidget(self._elapsed_value, 0, 1, Qt.AlignmentFlag.AlignLeft)

        # Row 0: Speed
        speed_label = QLabel("Speed:")
        speed_label.setStyleSheet("font-weight: bold;")
        self._speed_value = QLabel("0/s")
        grid_layout.addWidget(speed_label, 0, 2, Qt.AlignmentFlag.AlignRight)
        grid_layout.addWidget(self._speed_value, 0, 3, Qt.AlignmentFlag.AlignLeft)

        # Row 1: Corpus Size
        corpus_label = QLabel("Corpus Size:")
        corpus_label.setStyleSheet("font-weight: bold;")
        self._corpus_size_value = QLabel("0")
        grid_layout.addWidget(corpus_label, 1, 0, Qt.AlignmentFlag.AlignRight)
        grid_layout.addWidget(self._corpus_size_value, 1, 1, Qt.AlignmentFlag.AlignLeft)

        # Row 1: Solutions Found
        solutions_label = QLabel("Solutions Found:")
        solutions_label.setStyleSheet("font-weight: bold;")
        self._solutions_value = QLabel("0")
        grid_layout.addWidget(solutions_label, 1, 2, Qt.AlignmentFlag.AlignRight)
        grid_layout.addWidget(self._solutions_value, 1, 3, Qt.AlignmentFlag.AlignLeft)

        # Row 2: Executions
        executions_label = QLabel("Executions:")
        executions_label.setStyleSheet("font-weight: bold;")
        self._executions_value = QLabel("0")
        grid_layout.addWidget(executions_label, 2, 0, Qt.AlignmentFlag.AlignRight)
        grid_layout.addWidget(self._executions_value, 2, 1, Qt.AlignmentFlag.AlignLeft)

        # Row 2: Coverage
        coverage_label = QLabel("Coverage:")
        coverage_label.setStyleSheet("font-weight: bold;")
        self._coverage_value = QLabel("N/A")
        grid_layout.addWidget(coverage_label, 2, 2, Qt.AlignmentFlag.AlignRight)
        grid_layout.addWidget(self._coverage_value, 2, 3, Qt.AlignmentFlag.AlignLeft)

        # Set column stretch to make it look balanced
        grid_layout.setColumnStretch(1, 1)
        grid_layout.setColumnStretch(3, 1)

        stats_frame.setLayout(grid_layout)
        layout.addWidget(stats_frame)

        group.setLayout(layout)
        return group

    def _create_corpus_group(self) -> QWidget:
        """Create the corpus display group."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Header with count
        header_layout = QHBoxLayout()
        self._corpus_count_label = QLabel("Corpus (0 items)")
        font = self._corpus_count_label.font()
        font.setBold(True)
        self._corpus_count_label.setFont(font)
        header_layout.addWidget(self._corpus_count_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Table view
        self._corpus_table = QTableView()
        self._corpus_table.setModel(self._corpus_model)
        self._corpus_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._corpus_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._corpus_table.horizontalHeader().setStretchLastSection(True)
        self._corpus_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._corpus_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._corpus_table.selectionModel().selectionChanged.connect(self._on_corpus_selection_changed)
        layout.addWidget(self._corpus_table)

        # Detail view for selected item
        self._corpus_detail = QTextEdit()
        self._corpus_detail.setReadOnly(True)
        self._corpus_detail.setMaximumHeight(100)
        self._corpus_detail.setPlaceholderText("Select a corpus item to view details...")
        layout.addWidget(self._corpus_detail)

        widget.setLayout(layout)
        return widget

    def _create_solutions_group(self) -> QWidget:
        """Create the solutions display group."""
        widget = QWidget()
        layout = QVBoxLayout()

        # Header with count
        header_layout = QHBoxLayout()
        self._solutions_count_label = QLabel("Solutions (0 items)")
        font = self._solutions_count_label.font()
        font.setBold(True)
        self._solutions_count_label.setFont(font)
        header_layout.addWidget(self._solutions_count_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Table view
        self._solutions_table = QTableView()
        self._solutions_table.setModel(self._solutions_model)
        self._solutions_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._solutions_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self._solutions_table.horizontalHeader().setStretchLastSection(True)
        self._solutions_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._solutions_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._solutions_table.selectionModel().selectionChanged.connect(self._on_solutions_selection_changed)
        layout.addWidget(self._solutions_table)

        # Detail view for selected item
        self._solutions_detail = QTextEdit()
        self._solutions_detail.setReadOnly(True)
        self._solutions_detail.setMaximumHeight(100)
        self._solutions_detail.setPlaceholderText("Select a solution to view details...")
        layout.addWidget(self._solutions_detail)

        widget.setLayout(layout)
        return widget

    def _update_elapsed_time(self) -> None:
        """Update the elapsed time display."""
        if self._start_time is not None:
            import time
            elapsed = int(time.time() - self._start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            self._elapsed_value.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _refresh_corpus_and_solutions(self) -> None:
        """Refresh corpus and solutions from the job's cached data."""
        import logging
        _l = logging.getLogger(__name__)

        if self._active_fuzzer_job is None:
            _l.warning("Cannot refresh: no active fuzzer job")
            return

        try:
            # Read corpus/solutions from job instance variables
            # These are updated by the worker thread in a thread-safe way
            corpus_items = getattr(self._active_fuzzer_job, '_current_corpus_items', [])
            solutions_items = getattr(self._active_fuzzer_job, '_current_solutions_items', [])

            _l.info(f"Refreshed corpus: {len(corpus_items)} items, solutions: {len(solutions_items)} items")

            # Update corpus model and label
            self._corpus_model.set_corpus_items(corpus_items)
            self._corpus_count_label.setText(f"Corpus ({len(corpus_items)} items)")

            # Update solutions model and label
            self._solutions_model.set_corpus_items(solutions_items)
            self._solutions_count_label.setText(f"Solutions ({len(solutions_items)} items)")

        except Exception as e:
            _l.error(f"Error refreshing corpus/solutions: {e}", exc_info=True)

    def _update_aggregated_statistics(self) -> None:
        """Aggregate and display statistics from all workers."""
        if not self._worker_stats:
            return

        stats_lines = []
        stats_lines.append(f"Active Workers: {len(self._worker_stats)}")
        stats_lines.append("")

        # Aggregate stats across workers
        total_executions = 0
        total_corpus_size = 0
        total_objectives = 0
        total_edges_hit = 0
        total_edges_total = 0
        execs_per_sec_values = []

        for _worker_id, worker_stats in self._worker_stats.items():
            total_executions += worker_stats.get("executions", 0)
            total_corpus_size += worker_stats.get("corpus_size", 0)
            total_objectives += worker_stats.get("objective_size", 0)
            total_edges_hit = max(total_edges_hit, worker_stats.get("edges_hit", 0))
            total_edges_total = max(total_edges_total, worker_stats.get("edges_total", 0))

            execs_str = worker_stats.get("execs_per_sec", "")
            if execs_str:
                execs_per_sec_values.append(execs_str)

        # Display aggregated stats
        stats_lines.append(f"Total Executions: {total_executions:,}")
        stats_lines.append(f"Total Corpus Size: {total_corpus_size}")
        stats_lines.append(f"Total Objectives: {total_objectives}")

        if execs_per_sec_values:
            stats_lines.append(f"Exec/s: {', '.join(execs_per_sec_values)}")

        if total_edges_total > 0:
            coverage_pct = (total_edges_hit / total_edges_total) * 100.0
            stats_lines.append(f"Coverage: {total_edges_hit}/{total_edges_total} ({coverage_pct:.2f}%)")

        stats_lines.append("")
        stats_lines.append("Per-Worker Stats:")
        for worker_id, worker_stats in sorted(self._worker_stats.items()):
            fuzzer_type = worker_stats.get("fuzzer_type", "")
            executions = worker_stats.get("executions", 0)
            corpus = worker_stats.get("corpus_size", 0)
            stats_lines.append(f"  Worker {worker_id} [{fuzzer_type}]: {executions:,} execs, corpus: {corpus}")

        self._stats_text.setText("\n".join(stats_lines))

    def _update_statistics(self, data: dict[str, Any]) -> None:
        """Update the statistics display with final data."""
        # Handle raw text format - just show what we can
        if "raw_text" in data:
            # Can't parse, show unknown values
            self._corpus_size_value.setText("?")
            self._solutions_value.setText("?")
            self._executions_value.setText("?")
            self._speed_value.setText("?")
            return

        # Update corpus size
        if "corpus_size" in data:
            self._corpus_size_value.setText(str(data["corpus_size"]))
        elif "final_corpus_size" in data:
            self._corpus_size_value.setText(str(data["final_corpus_size"]))

        # Update solutions
        if "objective_size" in data:
            self._solutions_value.setText(str(data["objective_size"]))
        elif "final_solutions_size" in data:
            self._solutions_value.setText(str(data["final_solutions_size"]))

        # Update executions
        if "executions" in data:
            self._executions_value.setText(f"{data['executions']:,}")

        # Update speed
        if "execs_per_sec_pretty" in data or "execs_per_sec" in data:
            execs = data.get("execs_per_sec_pretty") or data.get("execs_per_sec", "0/s")
            self._speed_value.setText(str(execs))

        # Update coverage
        if "edges_hit" in data and "edges_total" in data:
            edges_hit = data["edges_hit"]
            edges_total = data["edges_total"]
            if edges_total and edges_total > 0:
                coverage_pct = (edges_hit / edges_total) * 100.0
                self._coverage_value.setText(f"{edges_hit}/{edges_total} ({coverage_pct:.2f}%)")
            else:
                self._coverage_value.setText(f"{edges_hit}/{edges_total}")

    def _on_corpus_selection_changed(self, selected, deselected) -> None:
        """Handle corpus item selection."""
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            item = self._corpus_model.get_item(row)
            if item:
                self._display_item_detail(item, self._corpus_detail)

    def _on_solutions_selection_changed(self, selected, deselected) -> None:
        """Handle solutions item selection."""
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            item = self._solutions_model.get_item(row)
            if item:
                self._display_item_detail(item, self._solutions_detail)

    def _display_item_detail(self, item: bytes, text_edit: QTextEdit) -> None:
        """Display detailed view of a corpus/solution item."""
        lines = []
        lines.append(f"Size: {len(item)} bytes")
        lines.append("")
        lines.append("Hex dump:")
        lines.append(self._format_hex_dump(item))
        lines.append("")
        lines.append("ASCII (printable):")
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in item)
        lines.append(ascii_str)

        text_edit.setText("\n".join(lines))

    def _format_hex_dump(self, data: bytes, width: int = 16) -> str:
        """Format bytes as a hex dump."""
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i : i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<{width*3}}  {ascii_part}")
        return "\n".join(lines)
