import json
from typing import Optional, Union, List, Tuple
from PySide2.QtCore import Qt
from PySide2.QtGui import QColor
from PySide2.QtWidgets import QApplication, QFileDialog, QInputDialog, QLineEdit, QMessageBox

from ...data.object_container import ObjectContainer
from ...logic import GlobalInfo
from ...logic.threads import gui_thread_schedule_async
from ...utils.io import isurl, download_url
from ...errors import InvalidURLError, UnexpectedStatusCodeError
from ..base_plugin import BasePlugin
from .trace_statistics import TraceStatistics
from .qpoi_viewer import QPOIViewer
from .multi_poi import MultiPOI
from .diagnose_handler import DiagnoseHandler


import logging
_l = logging.getLogger(__name__)
_l.setLevel('DEBUG')


class POIViewer(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace.instance.register_container('poi_trace', lambda: None, Optional[TraceStatistics],
                                                   'The trace of selected POI')
        self.workspace.instance.register_container('multi_poi', lambda: None, Optional[MultiPOI],
                                                   'POI list')

        self._viewers = []

        # self._pois = {}

        self._diagnose_handler = DiagnoseHandler()

        self.multi_poi.am_subscribe(self._on_poi_selected)

    def teardown(self):
        # I don't really know a better way to do this. tbh allowing arbitrary widget additions is probably intractable
        for viewer in self._viewers:
            viewer.hide()
        self._diagnose_handler.deactivate()

    #
    # Forwarding properties
    #

    @property
    def poi_trace(self) -> Union[ObjectContainer, Optional[TraceStatistics]]:
        return self.workspace.instance.poi_trace

    @property
    def multi_poi(self) -> Union[ObjectContainer, Optional[MultiPOI]]:
        return self.workspace.instance.multi_poi


    #
    # Event handlers
    #

    def _on_poi_selected(self):
        # redraw disassembly view
        view = self.workspace.view_manager.first_view_in_category('disassembly')
        if view is not None:
            view.redraw_current_graph()
        # refresh function table
        view = self.workspace.view_manager.first_view_in_category('functions')
        if view is not None:
            view.refresh()

    #
    # workspace initialiZation
    #

    def on_workspace_initialized(self, workspace):
        self._diagnose_handler.init(workspace)

    #
    # features for the disassembly view
    #

    GRAPH_TRACE_LEGEND_WIDTH = 30
    GRAPH_TRACE_LEGEND_SPACING = 20

    def instrument_disassembly_view(self, dview):
        _l.debug('instrument disassembly view')
        poi_viewer = QPOIViewer(self.workspace, dview, parent=dview, diagnose_handler=self._diagnose_handler)
        self._viewers.append(poi_viewer)

        poi_viewer.setMinimumWidth(500)

        dview.layout().addWidget(poi_viewer)
        # TODO: recover this back when we deliver the code
        # poi_viewer.hide()

    def color_block(self, addr):
        if not self.multi_poi.am_none and self.multi_poi.is_active_tab:
            return self.multi_poi.get_hit_miss_color(addr)
        return None

    # def handle_click_block(self, qblock, event):
    #     btn = event.button()
    #
    #     if QApplication.keyboardModifiers() == Qt.ControlModifier and btn == Qt.RightButton:
    #         if self.multi_poi is not None and self.multi_poi.am_obj is not None:
    #             the_trace = self.multi_poi.get_any_trace(qblock.addr)
    #             if the_trace is not None:
    #                 self.poi.am_obj = TraceStatistics(self.workspace, the_trace, self.multi_poi.base_addr)
    #                 self.poi.am_event()
    #                 return True
    #
    #     return False

    def draw_insn(self, qinsn, painter):
        # legend
        if not self.multi_poi.am_none and self.multi_poi.is_active_tab:
            return  # skip
        strata = self._gen_strata(qinsn.insn.addr)
        if strata is not None:
            legend_x = 0 - self.GRAPH_TRACE_LEGEND_WIDTH - self.GRAPH_TRACE_LEGEND_SPACING
            for (i, w) in strata:
                color = self.poi_trace.get_mark_color(qinsn.insn.addr, i)
                painter.setPen(color)
                painter.setBrush(color)
                painter.drawRect(legend_x, 0, w, qinsn.height)
                legend_x += w

    def _gen_strata(self, addr):
        if not self.poi_trace.am_none:
            # count is cached in trace.
            count = self.poi_trace.get_count(addr)

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
        if (not self.multi_poi.am_none) and self.multi_poi.is_active_tab:
            return self.multi_poi.get_percent_color(func)

        if not self.poi_trace.am_none:
            for itr_func in self.poi_trace.trace_func:
                if itr_func.bbl_addr == func.addr:
                    return QColor(0xf0, 0xe7, 0xda)
            return QColor(0xee, 0xee, 0xee)
        return None

    FUNC_COLUMNS = ('Coverage',)

    def extract_func_column(self, func, idx):
        assert idx == 0
        if self.multi_poi.am_none:
            cov = 0
            rend = ''
        else:
            cov = self.multi_poi.get_coverage(func)
            rend = "%.2f%%" % cov

        return cov, rend

    #
    # Menu
    #
    MENU_BUTTONS = [
        'Open/Add a POI record...',
        'Load POIs from Slacrs',
    ]
    ADD_POI = 0
    LOAD_POI_FROM_SLACRS = 1

    def handle_click_menu(self, idx):

        if idx < 0 or idx >= len(self.MENU_BUTTONS):
            return

        if self.workspace.instance.project.am_none:
            return

        mapping = {
            self.ADD_POI: self._menu_add_poi,
            self.LOAD_POI_FROM_SLACRS: self._menu_load_pois_from_slacrs,
        }

        mapping.get(idx)()

    def _menu_add_poi(self):
        _l.debug('adding poi')
        poi_record = self._open_poi()
        if poi_record is not None:
            id = poi_record["id"]
            poi_json = poi_record["poi"]
            # self._pois[id] = poi_json
            if self.multi_poi.am_none:
                self.multi_poi.am_obj = MultiPOI(self.workspace)
            self.multi_poi.am_obj.add_poi(id, poi_json)

            # this should call qpoi_reviewer._subscribe_add_poi asynchronisely
            self.multi_poi.am_event()

    def _menu_load_pois_from_slacrs(self):
        _l.debug('loading pois from slacrs')
        pois = self._diagnose_handler.get_pois()
        if self.multi_poi.am_none:
            self.multi_poi.am_obj = MultiPOI(self.workspace)
        for poi_object in pois:
            poi_json = json.loads(poi_object.poi)
            _l.debug('poi json: %s', poi_json)
            # self._pois[poi_object.id] =poi_json
            self.multi_poi.am_obj.add_poi(poi_object.id, poi_json)

        # this should call qpoi_reviewer._subscribe_add_poi asynchronisely
        self.multi_poi.am_event()


    def _open_poi(self, poi_path=None):
        if poi_path is None:
            poi_path = self._open_poi_dialog(tfilter='json (*.json)')

        if poi_path is not None:
            with open(poi_path, 'rb') as f:
                return json.load(f)

        return None

    def _open_poi_dialog(self, tfilter):
        file_path, _ = QFileDialog.getOpenFileName(None, "Open a POI", "", tfilter)
        try:
            with open(file_path, 'rb') as f:
                f.read(1)
        except FileNotFoundError:
            return None

        return file_path