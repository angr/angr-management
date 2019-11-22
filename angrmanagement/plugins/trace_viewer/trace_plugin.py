import os
import json
from typing import Optional
from PySide2.QtCore import Qt
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QHBoxLayout, QFileDialog, QInputDialog, QLineEdit

from angrmanagement.plugins.trace_viewer.qtrace_viewer import QTraceViewer

from ..base_plugin import BasePlugin
from .trace_statistics import TraceStatistics
from .multi_trace import MultiTrace

class TraceViewer(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace.instance.register_container('trace', lambda: None, Optional[TraceStatistics], 'The current trace')
        self.workspace.instance.register_container('multi_trace', lambda: None, Optional[MultiTrace], 'The current set of multiple traces')

        self._viewers = []

    def teardown(self):
        # I don't really know a better way to do this. tbh allowing arbitrary widget additions is probably intractable
        for trace_viewer in self._viewers:
            trace_viewer.hide()

    #
    # Forwarding properties
    #

    @property
    def trace(self):
        return self.workspace.instance.trace

    @property
    def multi_trace(self):
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
            if self.workspace.instance.multi_trace is not None:
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
            return self.workspace.instance.multi_trace.get_percent_color(func)

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

    MENU_BUTTONS = ['Open trace...', 'Open MultiTrace...']
    def handle_click_menu(self, idx):
        assert idx in (0, 1)

        if self.workspace.instance.project is None:
            return

        if idx == 0:
            self.open_trace()
        else:
            self.open_multi_trace()

    def open_trace(self):
        trace, baddr = self._open_trace_dialog()
        if baddr is None:
            return

        self.trace.am_obj = TraceStatistics(self.workspace, trace, baddr)
        self.trace.am_event()

    def open_multi_trace(self):
        trace, baddr = self._open_trace_dialog()
        if baddr is None:
            return

        self.multi_trace.am_obj = MultiTrace(self.workspace, trace, baddr)
        self.multi_trace.am_event()

    def _open_trace_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(None, "Open a trace", "", "json (*.json)")
        try:
            with open(file_path, 'r') as f:
                trace = json.load(f)
        except FileNotFoundError:
            return None, None
        # TODO: exception for json loading

        project = self.workspace.instance.project

        if file_path:
            baddr, _ = QInputDialog.getText(None, "Input Trace Base Address",
                                            "Base Address:", QLineEdit.Normal,
                                            hex(project.loader.main_object.mapped_base))

            try:
                return trace, int(baddr, 16)
            except ValueError:
                pass

        return None, None
