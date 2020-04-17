import json
from typing import Optional
from PySide2.QtCore import Qt
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QFileDialog, QInputDialog, QLineEdit, QMessageBox

from angrmanagement.plugins.trace_viewer.qtrace_viewer import QTraceViewer

from ...utils.io import isurl, download_url
from ...errors import InvalidURLError, UnexpectedStatusCodeError
from ..base_plugin import BasePlugin
from .trace_statistics import TraceStatistics
from .multi_trace import MultiTrace
from .afl_qemu_bitmap import AFLQemuBitmap


class TraceViewer(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace.instance.register_container('trace', lambda: None, Optional[TraceStatistics], 'The current trace')
        self.workspace.instance.register_container('multi_trace', lambda: None, Optional[MultiTrace], 'The current set of multiple traces')

        self.workspace.instance.register_method('open_bitmap_multi_trace', self.open_bitmap_multi_trace)

        self._viewers = []

    def teardown(self):
        # I don't really know a better way to do this. tbh allowing arbitrary widget additions is probably intractable
        for trace_viewer in self._viewers:
            trace_viewer.hide()

    #
    # Forwarding properties
    #

    @property
    def trace(self) -> Optional[TraceStatistics]:
        return self.workspace.instance.trace

    @property
    def multi_trace(self) -> Optional[MultiTrace]:
        return self.workspace.instance.multi_trace


    #
    # features for the disassembly view
    #

    GRAPH_TRACE_LEGEND_WIDTH = 30
    GRAPH_TRACE_LEGEND_SPACING = 20

    def instrument_disassembly_view(self, dview):
        trace_viewer = QTraceViewer(self.workspace, dview, parent=dview)
        self._viewers.append(trace_viewer)

        dview.layout().addWidget(trace_viewer)
        trace_viewer.hide()


    def color_block(self, addr):
        if self.multi_trace != None:
            return self.multi_trace.get_hit_miss_color(addr)
        return None

    def handle_click_block(self, qblock, event):
        btn = event.button()

        if QApplication.keyboardModifiers() == Qt.ControlModifier and btn == Qt.RightButton:
            if self.multi_trace is not None:
                the_trace = self.multi_trace.get_any_trace(qblock.addr)
                if the_trace is not None:
                    self.trace.am_obj = TraceStatistics(self.workspace, the_trace, self.multi_trace.base_addr)
                    self.trace.am_event()
                    return True

        return False

    def draw_insn(self, qinsn, painter):
        # legend
        strata = self._gen_strata(qinsn.insn.addr)
        if strata is not None:
            legend_x = 0 - self.GRAPH_TRACE_LEGEND_WIDTH - self.GRAPH_TRACE_LEGEND_SPACING
            for (i, w) in strata:
                color = self.trace.get_mark_color(qinsn.insn.addr, i)
                painter.setPen(color)
                painter.setBrush(color)
                painter.drawRect(legend_x, 0, w, qinsn.height)
                legend_x += w

    def _gen_strata(self, addr):
        if self.trace != None:
            # count is cached in trace.
            count = self.trace.get_count(addr)

            if count > self.GRAPH_TRACE_LEGEND_WIDTH:
                jump = count / self.GRAPH_TRACE_LEGEND_WIDTH
                return [(int(jump * i), 1) for i in
                        range(self.GRAPH_TRACE_LEGEND_WIDTH)]
            elif count > 0:
                width = self.GRAPH_TRACE_LEGEND_WIDTH // count
                remainder = self.GRAPH_TRACE_LEGEND_WIDTH % count
                return [(i, width + 1) for i in range(remainder)] + \
                       [(i, width) for i in range(remainder, count)]

        return None

    #
    # features for the functions view
    #

    def color_func(self, func):
        if self.multi_trace != None:
            return self.multi_trace.get_percent_color(func)

        if self.trace != None:
            for itr_func in self.trace.trace_func:
                if itr_func.bbl_addr == func.addr:
                    return QColor(0xf0, 0xe7, 0xda)
            return QColor(0xee, 0xee, 0xee)
        return None

    FUNC_COLUMNS = ('Coverage',)

    def extract_func_column(self, func, idx):
        assert idx == 0
        if self.multi_trace == None:
            cov = 0
            rend = ''
        else:
            cov = self.multi_trace.get_coverage(func)
            rend = "%.2f%%" % cov

        return cov, rend

    #
    # features for loading traces!
    #

    MENU_BUTTONS = ['Open trace...', 'Open MultiTrace...', 'Open AFL bitmap MultiTrace...']

    def handle_click_menu(self, idx):
        assert 0 <= idx <= 2

        if self.workspace.instance.project is None:
            return

        if idx == 0:
            self.open_trace()
        elif idx == 1:
            self.open_multi_trace()
        else:
            self.open_bitmap_multi_trace()

    def open_trace(self):
        trace, baddr = self._open_json_trace_dialog()
        if baddr is None:
            return

        self.trace.am_obj = TraceStatistics(self.workspace, trace, baddr)
        self.trace.am_event()

    def open_multi_trace(self):
        trace = self._open_json_trace_dialog()
        if trace is None:
            return
        base_addr = self._open_baseaddr_dialog(0x0)
        if base_addr is None:
            return

        self.multi_trace.am_obj = MultiTrace(self.workspace, trace, base_addr)
        self.multi_trace.am_event()

    def open_bitmap_multi_trace(self, trace_path=None, base_addr=None):

        if trace_path is None:
            trace_path = self._open_trace_dialog(filter='')
            if trace_path is None:
                return

        if base_addr is None:
            base_addr = self._open_baseaddr_dialog(0x0)
            if base_addr is None:
                return

        if isurl(trace_path):
            try:
                trace = download_url(trace_path, parent=self.workspace._main_window, to_file=False)
            except InvalidURLError:
                QMessageBox.critical(self.workspace._main_window,
                                     "Downloading failed",
                                     "angr management failed to download the file. The URL is invalid.")
                return
            except UnexpectedStatusCodeError as ex:
                QMessageBox.critical(self.workspace._main_window,
                                     "Downloading failed",
                                     "angr management failed to retrieve the header of the file. "
                                     "The HTTP request returned an unexpected status code %d." % ex.status_code)
                return
        else:
            with open(trace_path, 'rb') as f:
                trace = f.read()

        self.multi_trace.am_obj = AFLQemuBitmap(self.workspace, trace, base_addr)
        self.multi_trace.am_event()

    def _open_trace_dialog(self, filter):
        file_path, _ = QFileDialog.getOpenFileName(None, "Open a trace", "", filter)
        try:
            with open(file_path, 'rb') as f:
                f.read(1)
        except FileNotFoundError:
            return None

        return file_path

    def _open_baseaddr_dialog(self, default_base):
        base_addr, _ = QInputDialog.getText(None, "Input Trace Base Address",
                                            "Base Address:", QLineEdit.Normal,
                                            hex(default_base))
        try:
            return int(base_addr, 16)
        except ValueError:
            return None

    def _open_json_trace_dialog(self):
        project = self.workspace.instance.project
        trace_file_name = self._open_trace_dialog(filter='json (*.json)')
        base_addr = self._open_baseaddr_dialog(project.loader.main_object.mapped_base)

        if trace_file_name is None or base_addr is None:
            return None, None

        with open(trace_file_name, 'r') as f:
            trace = json.load(f)
        return trace, base_addr
