from __future__ import annotations

import json
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QLineEdit, QMessageBox

from angrmanagement.errors import InvalidURLError, UnexpectedStatusCodeError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.plugins.base_plugin import BasePlugin
from angrmanagement.utils.io import download_url, isurl

from .afl_qemu_bitmap import AFLQemuBitmap
from .multi_trace import MultiTrace
from .qtrace_viewer import QTraceViewer
from .trace_statistics import TraceStatistics

if TYPE_CHECKING:
    from angrmanagement.data.object_container import ObjectContainer
    from angrmanagement.ui.workspace import Workspace


class TraceViewer(BasePlugin):
    def __init__(self, workspace: Workspace) -> None:
        super().__init__(workspace)

        self.workspace.main_instance.register_container(
            "trace", lambda: None, TraceStatistics | None, "The current trace"
        )
        self.workspace.main_instance.register_container(
            "multi_trace", lambda: None, MultiTrace | None, "The current set of multiple traces"
        )

        # Register event callbacks
        # self.trace.am_subscribe(self._on_trace_updated)
        self.multi_trace.am_subscribe(self._on_trace_updated)

        self._viewers = []

    def teardown(self) -> None:
        # I don't really know a better way to do this. tbh allowing arbitrary widget additions is probably intractable
        for trace_viewer in self._viewers:
            trace_viewer.hide()

    #
    # Forwarding properties
    #

    @property
    def trace(self) -> ObjectContainer | TraceStatistics | None:
        return self.workspace.main_instance.trace

    @property
    def multi_trace(self) -> ObjectContainer | MultiTrace | None | AFLQemuBitmap:
        return self.workspace.main_instance.multi_trace

    #
    # Event handlers
    #

    def _on_trace_updated(self) -> None:
        # redraw disassembly view
        view = self.workspace.view_manager.first_view_in_category("disassembly")
        if view is not None:
            view.redraw_current_graph()
        # refresh function table
        view = self.workspace.view_manager.first_view_in_category("functions")
        if view is not None:
            view.refresh()

    URL_ACTIONS = ["openbitmap", "opentrace"]

    def handle_url_action(self, action, kwargs):
        if action == "openbitmap":
            try:
                base = int(kwargs["base"], 16)
            except (ValueError, KeyError):
                base = None
            gui_thread_schedule_async(GlobalInfo.main_window.bring_to_front)
            gui_thread_schedule_async(
                self.open_bitmap_multi_trace,
                args=(kwargs["path"],),
                kwargs={
                    "base_addr": base,
                },
            )
        elif action == "opentrace":
            try:
                base = int(kwargs["base"], 16)
            except (ValueError, KeyError):
                base = None
            path = kwargs["path"]
            gui_thread_schedule_async(GlobalInfo.main_window.bring_to_front)
            gui_thread_schedule_async(
                self.add_trace,
                kwargs={
                    "trace_path": path,
                    "base_addr": base,
                },
            )
        else:
            raise ValueError("Trace plugin cannot handle url action " + action)

    #
    # features for the disassembly view
    #

    GRAPH_TRACE_LEGEND_WIDTH = 30
    GRAPH_TRACE_LEGEND_SPACING = 20

    def instrument_disassembly_view(self, dview) -> None:
        trace_viewer = QTraceViewer(self.workspace, dview, parent=dview)
        self._viewers.append(trace_viewer)

        dview.layout().addWidget(trace_viewer)
        trace_viewer.hide()

    def color_block(self, addr: int):
        if not self.multi_trace.am_none:
            if isinstance(self.multi_trace.am_obj, MultiTrace) and not self.multi_trace.is_active_tab:
                return None
            return self.multi_trace.get_hit_miss_color(addr)
        return None

    def handle_click_block(self, qblock, event) -> bool:
        btn = event.button()

        if (
            QApplication.keyboardModifiers() == Qt.KeyboardModifier.ControlModifier
            and btn == Qt.MouseButton.RightButton
            and self.multi_trace is not None
            and self.multi_trace.am_obj is not None
        ):
            the_trace = self.multi_trace.get_any_trace(qblock.addr)
            if the_trace is not None:
                self.trace.am_obj = TraceStatistics(self.workspace, the_trace, self.multi_trace.base_addr)
                self.trace.am_event()
                return True

        return False

    def draw_insn(self, qinsn, painter) -> None:
        # legend
        if (
            not self.multi_trace.am_none
            and isinstance(self.multi_trace.am_obj, MultiTrace)
            and not self.multi_trace.is_active_tab
        ):
            return  # skip
        strata = self._gen_strata(qinsn.insn.addr)
        if strata is not None:
            legend_x = 0 - self.GRAPH_TRACE_LEGEND_WIDTH - self.GRAPH_TRACE_LEGEND_SPACING
            for i, w in strata:
                color = self.trace.get_mark_color(qinsn.insn.addr, i)
                painter.setPen(color)
                painter.setBrush(color)
                painter.drawRect(legend_x, 0, w, qinsn.height)
                legend_x += w

    def _gen_strata(self, addr: int):
        if not self.trace.am_none:
            # count is cached in trace.
            count = self.trace.get_count(addr)

            if count > self.GRAPH_TRACE_LEGEND_WIDTH:
                jump = count / self.GRAPH_TRACE_LEGEND_WIDTH
                return [(int(jump * i), 1) for i in range(self.GRAPH_TRACE_LEGEND_WIDTH)]
            elif count > 0:
                width = self.GRAPH_TRACE_LEGEND_WIDTH // count
                remainder = self.GRAPH_TRACE_LEGEND_WIDTH % count
                return [(i, width + 1) for i in range(remainder)] + [(i, width) for i in range(remainder, count)]

        return None

    #
    # features for the functions view
    #

    def color_func(self, func):
        if not self.multi_trace.am_none:
            if isinstance(self.multi_trace.am_obj, MultiTrace):
                if self.multi_trace.is_active_tab:
                    return self.multi_trace.get_percent_color(func)
            elif isinstance(self.multi_trace.am_obj, AFLQemuBitmap):
                return self.multi_trace.get_percent_color(func)
            else:
                # you should not reach here
                raise RuntimeError("Impossible happened")

        if not self.trace.am_none:
            if func.addr in self.trace.func_addr_in_trace:
                return QColor(0xF0, 0xE7, 0xDA)
            return QColor(0xEE, 0xEE, 0xEE)
        return None

    FUNC_COLUMNS = ("Coverage",)

    def extract_func_column(self, func, idx: int):
        assert idx == 0
        if self.multi_trace.am_none:
            cov = 0
            rend = ""
        else:
            cov = self.multi_trace.get_coverage(func)
            rend = f"{cov:.2f}%"

        return cov, rend

    #
    # features for loading traces!
    #

    MENU_BUTTONS = [
        "Open/Add trace...",
        "Clear trace",
        "Open AFL bitmap...",
        "Open inverted AFL bitmap...",
        "Reset AFL bitmap",
    ]
    ADD_TRACE_ID = 0
    RESET_TRACE_ID = 1
    OPEN_AFL_BITMAP_ID = 2
    OPEN_AFL_BITMAP_INVERTED_ID = 3
    RESET_AFL_BITMAP = 4
    OPEN_TRACES_FROM_CHECRS = 5

    def handle_click_menu(self, idx: int) -> None:
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.main_instance.project.am_none:
            return

        mapping = {
            self.ADD_TRACE_ID: self.add_trace,
            self.RESET_TRACE_ID: self.reset_trace,
            self.OPEN_AFL_BITMAP_ID: self.open_bitmap_multi_trace,
            self.OPEN_AFL_BITMAP_INVERTED_ID: self.open_inverted_bitmap_multi_trace,
            self.RESET_AFL_BITMAP: self.reset_bitmap,
        }

        mapping.get(idx)()

    def add_trace(self, trace_path=None, base_addr=None) -> None:
        trace, base_addr = self._open_trace(trace_path, base_addr)
        if trace is None or base_addr is None:
            return

        self._add_trace(trace, base_addr)

    def reset_trace(self) -> None:
        self.trace.am_obj = None
        self.trace.am_event()
        self.multi_trace.am_obj = None
        self.multi_trace.am_event()

    def open_bitmap_multi_trace(self, trace_path=None, base_addr=None) -> None:
        r = self._open_bitmap_multi_trace(trace_path, base_addr)
        if r is None:
            return
        trace, base_addr = r
        self.multi_trace.am_obj = AFLQemuBitmap(self.workspace, trace, base_addr)
        self.multi_trace.am_event()

    def open_inverted_bitmap_multi_trace(self, trace_path=None, base_addr=None) -> None:
        r = self._open_bitmap_multi_trace(trace_path, base_addr)
        if r is None:
            return
        trace, base_addr = r
        self.multi_trace.am_obj = AFLQemuBitmap(self.workspace, trace, base_addr, bits_inverted=True)
        self.multi_trace.am_event()

    def reset_bitmap(self) -> None:
        self.multi_trace.am_obj = None
        self.multi_trace.am_event()

    def _open_bitmap_multi_trace(self, trace_path, base_addr):
        if trace_path is None:
            trace_path = self._open_trace_dialog(tfilter="")
            if trace_path is None:
                return None

        if base_addr is None:
            base_addr = self._open_baseaddr_dialog(0x4000000000)
            if base_addr is None:
                return None

        if isurl(trace_path):
            try:
                trace = download_url(trace_path, parent=self.workspace._main_window, to_file=False)
            except InvalidURLError:
                QMessageBox.critical(
                    self.workspace._main_window,
                    "Downloading failed",
                    "angr management failed to download the file. The URL is invalid.",
                )
                return None
            except UnexpectedStatusCodeError as ex:
                QMessageBox.critical(
                    self.workspace._main_window,
                    "Downloading failed",
                    "angr management failed to retrieve the header of the file. "
                    "The HTTP request returned an unexpected status code %d." % ex.status_code,
                )
                return None
        else:
            with open(trace_path, "rb") as f:
                trace = f.read()

        return trace, base_addr

    def _open_trace(self, trace_path, base_addr):
        if trace_path is None:
            return self._open_json_trace_dialog()
        else:
            if isurl(trace_path):
                try:
                    trace_bytes = download_url(trace_path, parent=self.workspace._main_window, to_file=False)
                    trace = json.loads(trace_bytes)
                except InvalidURLError:
                    QMessageBox.critical(
                        self.workspace._main_window,
                        "Downloading failed",
                        "angr management failed to download the file. The URL is invalid.",
                    )
                    trace = None
                except UnexpectedStatusCodeError as ex:
                    QMessageBox.critical(
                        self.workspace._main_window,
                        "Downloading failed",
                        "angr management failed to retrieve the header of the file. "
                        "The HTTP request returned an unexpected status code %d." % ex.status_code,
                    )
                    trace = None
            else:
                with open(trace_path) as f:
                    trace = json.load(f)

            if base_addr is None:
                base_addr = self._open_baseaddr_dialog(0x4000000000)

            return trace, base_addr

    def _open_trace_dialog(self, tfilter):
        file_path, _ = QFileDialog.getOpenFileName(None, "Open a trace", "", tfilter)
        try:
            with open(file_path, "rb") as f:
                f.read(1)
        except FileNotFoundError:
            return None

        return file_path

    def _open_baseaddr_dialog(self, default_base):
        base_addr, _ = QInputDialog.getText(
            None, "Input Trace Base Address", "Base Address:", QLineEdit.Normal, hex(default_base)
        )
        try:
            return int(base_addr, 16)
        except ValueError:
            return None

    def _open_json_trace_dialog(self) -> tuple[list[int] | None, int | None]:
        # project = self.workspace.instance.project
        trace_file_name = self._open_trace_dialog(tfilter="json (*.json)")

        if trace_file_name is None:
            return None, None

        with open(trace_file_name) as f:
            trace = json.load(f)

        if not isinstance(trace, dict):
            QMessageBox.critical(
                self.workspace._main_window,
                "Incorrect trace format",
                "Failed to open the JSON trace. We expect the JSON trace to be a dict.",
            )
            return None, None
        elif "bb_addrs" not in trace:
            QMessageBox.critical(
                self.workspace._main_window,
                "Incorrect trace format",
                "Failed to open the JSON trace. We expect the JSON trace to contain the field 'bb_addrs'.",
            )
            return None, None
        elif not isinstance(trace["bb_addrs"], list):
            QMessageBox.critical(
                self.workspace._main_window,
                "Incorrect trace format",
                "Failed to open the JSON trace. We expect the JSON trace bb_addrs field to be a list of integers.",
            )
            return None, None

        base_addr = self._open_baseaddr_dialog(0x4000000000)

        return trace, base_addr

    def _add_trace(self, trace, base_addr) -> None:
        if self.multi_trace.am_obj is None:
            self.multi_trace.am_obj = MultiTrace(self.workspace)
        self.trace.am_obj = self.multi_trace.am_obj.add_trace(trace, base_addr)
        self.multi_trace.am_event()
        self.trace.am_event()
