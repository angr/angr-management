from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, QTimer
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from sortedcontainers import SortedDict

from angrmanagement.plugins.trace_viewer.afl_qemu_bitmap import AFLQemuBitmap
from angrmanagement.ui.views.hex_view import HexGraphicsView
from angrmanagement.ui.views.view import InstanceView

if TYPE_CHECKING:
    from .fuzzer import FuzzerExecutor

log = logging.getLogger(name=__name__)


def get_item_texts(list_widget: QListWidget):
    return [list_widget.item(i).text() for i in range(list_widget.count())]


class OutputsWidget(QWidget):
    def __init__(self, executor: FuzzerExecutor, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.executor = executor

        self._init_widgets()

    def _init_widgets(self):
        self.outputs_list_widget = QListWidget()
        self.outputs_list_widget.setMinimumSize(200, 200)
        self.outputs_list_widget.itemClicked.connect(self.update_preview_output)
        self.solutions_list_widget = QListWidget()
        self.solutions_list_widget.setMinimumSize(200, 200)
        self.solutions_list_widget.itemClicked.connect(self.update_preview_solution)
        self.preview_widget = HexGraphicsView()
        self.preview_widget.setMinimumSize(200, 200)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)

        top_layout = QHBoxLayout()
        lists_layout = QVBoxLayout()
        lists_layout.addWidget(QLabel("Interesting Inputs"))
        lists_layout.addWidget(self.outputs_list_widget)
        lists_layout.addWidget(QLabel("Crashing Inputs"))
        lists_layout.addWidget(self.solutions_list_widget)
        lists_layout.addWidget(self.refresh_button)
        top_layout.addLayout(lists_layout)
        top_layout.addWidget(self.preview_widget)
        self.setLayout(top_layout)

        self.refresh()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

    def refresh(self):
        self.outputs_list_widget.addItems(
            [i for i in self.executor.get_outputs_list() if i not in get_item_texts(self.outputs_list_widget)]
        )
        self.solutions_list_widget.addItems(
            [i for i in self.executor.get_solutions_list() if i not in get_item_texts(self.solutions_list_widget)]
        )

    def update_preview_output(self, output_id):
        self.preview_widget.hex.set_data(self.executor.get_output(output_id.text()))

    def update_preview_solution(self, solution_id):
        self.preview_widget.hex.set_data(self.executor.get_solution(solution_id.text()))


class BitmapWidget(QWidget):
    def __init__(self, workspace, executor: FuzzerExecutor, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace = workspace
        self.executor = executor

        self._init_widgets()

    def _init_widgets(self):
        self.refresh_button = QPushButton("Load latest bitmap")
        self.refresh_button.clicked.connect(self.refresh)

        layout = QVBoxLayout()
        layout.addWidget(self.refresh_button)
        self.setLayout(layout)

    def refresh(self):
        self.workspace.main_instance.multi_trace.am_obj = AFLQemuBitmap(
            self.workspace, self.executor.get_bitmap(), self.executor.base_addr
        )
        self.workspace.main_instance.multi_trace.am_event()


class CustomTableView(QTableView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.model = QStandardItemModel(self)
        self.setModel(self.model)
        self.columns = {}  # Maps column headers to column indices

    def add_row_from_dict(self, row_data: dict[str, str]) -> None:
        """Adds a row to the table from a dictionary."""
        for header, _ in row_data.items():
            if header not in self.columns:
                # New column, add it and update mapping
                col_index = self.model.columnCount()
                self.columns[header] = col_index
                self.model.setHorizontalHeaderItem(col_index, QStandardItem(header))
            else:
                col_index = self.columns[header]

        # Find the next available row (empty) in this column or append to the end
        row_index = self.model.rowCount()
        for header, value in row_data.items():
            col_index = self.columns[header]
            item = QStandardItem(str(value))
            self.model.setItem(row_index, col_index, item)


class EventsWidget(QWidget):
    def __init__(self, workspace, executor: FuzzerExecutor, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace = workspace
        self.executor = executor
        self.events = SortedDict()

        self._init_widgets()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)

    def _init_widgets(self):
        self.table = CustomTableView()
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        self.setLayout(layout)

    def refresh(self):
        all_events = self.executor.get_events_list()
        for event in all_events:
            if event not in self.events:
                self.events[event] = self.executor.get_event(event)
                self.table.add_row_from_dict(self.events[event])


class FuzzerView(InstanceView):
    """
    Log view displays logging output.
    """

    executor: FuzzerExecutor

    def __init__(self, workspace, default_docking_position, instance, executor: FuzzerExecutor):
        super().__init__("fuzzer", workspace, default_docking_position, instance)

        self.base_caption = "Fuzzer"
        self.executor = executor

        self._init_widgets()
        self.reload()

    def closeEvent(self, event):
        super().closeEvent(event)

    def reload(self):
        pass

    @staticmethod
    def minimumSizeHint(*args, **kwargs):  # pylint: disable=unused-argument
        return QSize(0, 50)

    def _init_widgets(self):
        tab_widget = QTabWidget()

        # stdout_tab = StreamWidget(self.executor.process.stdout)
        output_tab = OutputsWidget(self.executor)
        bitmap_tab = BitmapWidget(self.workspace, self.executor)
        events_tab = EventsWidget(self.workspace, self.executor)

        tab_widget.addTab(output_tab, "Inputs")
        tab_widget.addTab(events_tab, "Events")
        tab_widget.addTab(bitmap_tab, "Bitmap")
        # tab_widget.addTab(stdout_tab, "Log")

        layout = QVBoxLayout()
        layout.addWidget(tab_widget)

        self.setLayout(layout)
