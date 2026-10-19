from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from angrmanagement.config.color import Color
from angrmanagement.errors import InvalidURLError, UnexpectedStatusCodeError
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.plugins.base_plugin import BasePlugin, qt_frontend
from angrmanagement.present.marks import Mark
from angrmanagement.utils.io import download_url, isurl

from .afl_qemu_bitmap import AFLQemuBitmap
from .multi_trace import MultiTrace
from .trace_statistics import TraceStatistics

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.object_container import ObjectContainer
    from angrmanagement.ui.workspace import Workspace


def _qcolor(color: Any) -> Any:
    """A colour the trace gives (neutral, or a QColor the Qt strip read from its legend) as a QColor."""
    return color.to_qcolor() if isinstance(color, Color) else color


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
            if qt_frontend():
                trace_viewer.hide()
            else:
                trace_viewer.remove()

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
        for strip in self._viewers:
            refresh_trace = getattr(strip, "refresh_trace", None)
            if refresh_trace is not None:
                refresh_trace()
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
        if qt_frontend():
            from .qtrace_viewer import QTraceViewer  # pylint:disable=import-outside-toplevel

            trace_viewer = QTraceViewer(self.workspace, dview, parent=dview)
            self._viewers.append(trace_viewer)

            dview.layout().addWidget(trace_viewer)
            trace_viewer.hide()
            return
        # the terminal's disassembly view: the trace strip beside the graph
        from .tui_strip import TraceStrip  # pylint:disable=import-outside-toplevel

        strip = TraceStrip(self.workspace, dview)
        self._viewers.append(strip)
        dview.add_plugin_widget(strip)

    def block_style(self, addr: int):
        if not self.multi_trace.am_none:
            if isinstance(self.multi_trace.am_obj, MultiTrace) and not self.multi_trace.is_active_tab:
                return None
            return self.multi_trace.get_hit_miss_color(addr)
        return None

    def handle_click_block(self, qblock, event) -> bool:
        from PySide6.QtCore import Qt  # pylint:disable=import-outside-toplevel
        from PySide6.QtWidgets import QApplication  # pylint:disable=import-outside-toplevel

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
                color = _qcolor(self.trace.get_mark_color(qinsn.insn.addr, i))
                painter.setPen(color)
                painter.setBrush(color)
                painter.drawRect(legend_x, 0, w, qinsn.height)
                legend_x += w

    def decorate_insn(self, addr: int, view) -> list[Mark]:
        """How often the trace passed the instruction, as a mark: the terminal's form of the Qt legend strata."""
        if qt_frontend() or self.trace.am_none:
            return []
        if isinstance(self.multi_trace.am_obj, MultiTrace) and not self.multi_trace.is_active_tab:
            return []
        count = self.trace.get_count(addr)
        return [Mark(f"{count}×", "disasm.mark.trace", "before", 1)] if count > 0 else []

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

    def func_style(self, func):
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
                return Color(0xF0, 0xE7, 0xDA)
            return Color(0xEE, 0xEE, 0xEE)
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

    # The questions below take a continuation, so that they ask through the UI services in either frontend: the Qt
    # dialogs answer at once, the terminal's screens when the user does.

    def add_trace(self, trace_path=None, base_addr=None) -> None:
        def then(trace, base) -> None:
            if trace is not None and base is not None:
                self._add_trace(trace, base)

        self._open_trace(trace_path, base_addr, then)

    def reset_trace(self) -> None:
        self.trace.am_obj = None
        self.trace.am_event()

        self.multi_trace.am_obj = None
        self.multi_trace.am_event()

    def open_bitmap_multi_trace(self, trace_path=None, base_addr=None) -> None:
        def then(trace, base) -> None:
            self.multi_trace.am_obj = AFLQemuBitmap(self.workspace, trace, base)
            self.multi_trace.am_event()

        self._open_bitmap_multi_trace(trace_path, base_addr, then)

    def open_inverted_bitmap_multi_trace(self, trace_path=None, base_addr=None) -> None:
        def then(trace, base) -> None:
            self.multi_trace.am_obj = AFLQemuBitmap(self.workspace, trace, base, bits_inverted=True)
            self.multi_trace.am_event()

        self._open_bitmap_multi_trace(trace_path, base_addr, then)

    def reset_bitmap(self) -> None:
        self.multi_trace.am_obj = None
        self.multi_trace.am_event()

    @staticmethod
    def _message(title: str, text: str) -> None:
        GlobalInfo.ui_services.message("critical", title, text)

    def _download(self, url: str) -> bytes | None:
        try:
            return download_url(url, parent=self.workspace._main_window, to_file=False)
        except InvalidURLError:
            self._message("Downloading failed", "angr management failed to download the file. The URL is invalid.")
        except UnexpectedStatusCodeError as ex:
            self._message(
                "Downloading failed",
                "angr management failed to retrieve the header of the file. "
                f"The HTTP request returned an unexpected status code {ex.status_code}.",
            )
        return None

    def _open_bitmap_multi_trace(self, trace_path, base_addr, then: Callable[[Any, int], None]) -> None:
        """Get the bitmap at ``trace_path`` (asked for when None) and its base address (asked for when None)."""
        if trace_path is None:
            self._open_trace_dialog(
                "", lambda path: self._open_bitmap_multi_trace(path, base_addr, then) if path is not None else None
            )
            return
        if base_addr is None:
            self._open_baseaddr_dialog(
                0x4000000000,
                lambda base: self._open_bitmap_multi_trace(trace_path, base, then) if base is not None else None,
            )
            return
        if isurl(trace_path):
            trace = self._download(trace_path)
            if trace is None:
                return
        else:
            with open(trace_path, "rb") as f:
                trace = f.read()
        then(trace, base_addr)

    def _open_trace(self, trace_path, base_addr, then: Callable[[Any, Any], None]) -> None:
        if trace_path is None:
            self._open_json_trace_dialog(then)
            return
        if isurl(trace_path):
            trace_bytes = self._download(trace_path)
            trace = json.loads(trace_bytes) if trace_bytes is not None else None
        else:
            with open(trace_path) as f:
                trace = json.load(f)
        if base_addr is None:
            self._open_baseaddr_dialog(0x4000000000, lambda base: then(trace, base))
            return
        then(trace, base_addr)

    @staticmethod
    def _open_trace_dialog(tfilter, then: Callable[[str | None], None]) -> None:
        def picked(files: list[str]) -> None:
            file_path = files[0] if files else ""
            try:
                with open(file_path, "rb") as f:
                    f.read(1)
            except FileNotFoundError:
                then(None)
                return
            then(file_path)

        GlobalInfo.ui_services.pick_open_files_async("Open a trace", "", tfilter, False, picked)

    @staticmethod
    def _open_baseaddr_dialog(default_base, then: Callable[[int | None], None]) -> None:
        def answered(base_addr: str | None) -> None:
            try:
                then(int(base_addr or "", 16))
            except ValueError:
                then(None)

        GlobalInfo.ui_services.prompt_text_async(
            "Input Trace Base Address", "Base Address:", hex(default_base), answered
        )

    def _open_json_trace_dialog(self, then: Callable[[Any, Any], None]) -> None:
        def picked(trace_file_name: str | None) -> None:
            if trace_file_name is None:
                then(None, None)
                return
            with open(trace_file_name) as f:
                trace = json.load(f)
            if not isinstance(trace, dict):
                self._message(
                    "Incorrect trace format", "Failed to open the JSON trace. We expect the JSON trace to be a dict."
                )
                then(None, None)
                return
            if "bb_addrs" not in trace:
                self._message(
                    "Incorrect trace format",
                    "Failed to open the JSON trace. We expect the JSON trace to contain the field 'bb_addrs'.",
                )
                then(None, None)
                return
            if not isinstance(trace["bb_addrs"], list):
                self._message(
                    "Incorrect trace format",
                    "Failed to open the JSON trace. We expect the JSON trace bb_addrs field to be a list of integers.",
                )
                then(None, None)
                return
            self._open_baseaddr_dialog(0x4000000000, lambda base: then(trace, base))

        self._open_trace_dialog("json (*.json)", picked)

    def _add_trace(self, trace, base_addr) -> None:
        if self.multi_trace.am_obj is None:
            self.multi_trace.am_obj = MultiTrace(self.workspace)
        self.trace.am_obj = self.multi_trace.am_obj.add_trace(trace, base_addr)
        self.multi_trace.am_event()
        self.trace.am_event()
