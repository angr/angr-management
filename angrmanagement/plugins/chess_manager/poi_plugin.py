import json
import logging
from copy import deepcopy
import os
from typing import Optional, Union

from PySide2.QtGui import QColor
from PySide2.QtWidgets import QFileDialog, QMessageBox

from ...data.object_container import ObjectContainer
from ..base_plugin import BasePlugin
from .trace_statistics import TraceStatistics
from .qpoi_viewer import POIView, EMPTY_POI
from .multi_poi import MultiPOI
from .diagnose_handler import DiagnoseHandler


_l = logging.getLogger(__name__)
# _l.setLevel('DEBUG')


class POIViewer(BasePlugin):
    """
    POI Viewer Plugin
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.workspace.instance.register_container('poi_trace', lambda: None, Optional[TraceStatistics],
                                                   'The trace of selected POI')
        self.workspace.instance.register_container('multi_poi', lambda: None, Optional[MultiPOI],
                                                   'POI list')

        self._views = []

        self._diagnose_handler = DiagnoseHandler()

        self.poi_view = POIView(self.workspace, "right", self._diagnose_handler)
        self.workspace.add_view(self.poi_view)
        self._views.append(self.poi_view)

        self.multi_poi.am_subscribe(self._on_poi_selected)

    def teardown(self):
        for view in self._views:
            view.close()
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
    # workspace initialization
    #

    def on_workspace_initialized(self, _):
        self._diagnose_handler.init(self.workspace)

    #
    # features for the disassembly view
    #

    GRAPH_TRACE_LEGEND_WIDTH = 30
    GRAPH_TRACE_LEGEND_SPACING = 20

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
        'Create a POI from a JSON file...',
        'Load POIs from CHECRS',
    ]
    ADD_POI = 0
    LOAD_POI_FROM_SLACRS = 1

    def handle_click_menu(self, idx):
        if idx < 0 or idx >= len(self.MENU_BUTTONS):
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
            poi_id = poi_record["id"]
            poi_json = poi_record["poi"]
            # self._pois[id] = poi_json
            if self.multi_poi.am_none:
                self.multi_poi.am_obj = MultiPOI(self.workspace)
            self.multi_poi.am_obj.add_poi(poi_id, poi_json)

            # this should call qpoi_reviewer._subscribe_add_poi asynchronisely
            self.multi_poi.am_event()

    def _menu_load_pois_from_slacrs(self):
        _l.debug('loading pois from slacrs')
        pois = self._diagnose_handler.get_pois()
        if not pois:
            return

        if self.multi_poi.am_none:
            self.multi_poi.am_obj = MultiPOI(self.workspace)
        for poi_object in pois:
            _l.debug('poi: %s', poi_object.poi)
            if poi_object.poi != '':
                poi_json = json.loads(poi_object.poi)
            else:
                poi_json = deepcopy(EMPTY_POI)
            _l.debug('poi json: %s', poi_json)
            # self._pois[poi_object.id] =poi_json
            self.multi_poi.am_obj.add_poi(poi_object.id, poi_json)

        # this should call qpoi_reviewer._subscribe_add_poi asynchronisely
        self.multi_poi.am_event()

    def _open_poi(self, poi_path=None):
        if poi_path is None:
            poi_path = self._open_poi_dialog(tfilter='JSON files (*.json)')

        if poi_path is not None:
            with open(poi_path, 'r') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError as ex:
                    QMessageBox.critical(self.workspace.main_window,
                                         "JSON decoding error",
                                         f"Cannot decode {poi_path} as a JSON file. Exception: {ex}")
                    return None

        return None

    @staticmethod
    def _open_poi_dialog(tfilter):
        file_path, _ = QFileDialog.getOpenFileName(None, "Open a POI", "", tfilter)
        if not os.path.isfile(file_path):
            return None

        return file_path
