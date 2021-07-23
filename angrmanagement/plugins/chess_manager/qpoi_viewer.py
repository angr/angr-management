from uuid import uuid4
from copy import deepcopy
import logging

from PySide2.QtWidgets import QWidget, QVBoxLayout, QGraphicsScene, QGraphicsView, QGraphicsItemGroup, QMessageBox, \
    QTabWidget, QAbstractItemView, QMenu, QTableWidget, QTableWidgetItem, QHeaderView
from PySide2.QtGui import QPen, QBrush, QLinearGradient, QColor, QPainter, QImage, QFont, QContextMenuEvent
from PySide2.QtCore import Qt, QPoint

from angrmanagement.ui.views.view import BaseView

from .trace_statistics import TraceStatistics
from .multi_poi import MultiPOI

_l = logging.getLogger(name=__name__)

EMPTY_POI = {
    'category': '',
    'output': {
        'function': None,
        'bbl': None,
        'base': None,
        'bbl_history': None,
        'diagnose': None
    }
}


class QPOIViewer(QWidget):
    """
    POI Viewer QWidget
    """

    TAG_SPACING = 50
    LEGEND_X = -50
    LEGEND_Y = 0
    LEGEND_WIDTH = 10

    TRACE_FUNC_X = 0
    TRACE_FUNC_Y = 0
    TRACE_FUNC_WIDTH = 50
    TRACE_FUNC_MINHEIGHT = 1000

    TAB_HEADER_SIZE = 40
    MAX_WINDOW_SIZE = 500

    MARK_X = LEGEND_X
    MARK_WIDTH = TRACE_FUNC_X - LEGEND_X + TRACE_FUNC_WIDTH
    MARK_HEIGHT = 1

    POIID_COLUMN = 0
    CRASH_COLUMN = 1
    CATEGORY_COLUMN = 2
    DIAGNOSE_COLUMN = 3
    COLUMN_FIELD = ['id', 'bbl', 'category', 'diagnose']


    def __init__(self, workspace, parent=None, diagnose_handler=None):
        super().__init__(parent=parent)
        self.workspace = workspace
        self._diagnose_handler = diagnose_handler

        self.mark = None
        self.legend = None
        self.legend_height = 0
        self.legend_img = None
        self.trace_func_unit_height = 0

        self.trace_func = None
        self.trace_id = None

        self.tabView = None
        self.traceView = None
        self.traceScene = None
        self.POITraceTab = None
        self.multiPOITab : QWidget = None
        self.multiPOIList : QTableWidget = None

        self.mark = None
        self.curr_position = 0
        self._use_precise_position = False
        self._selected_traces = []
        self._selected_poi = None

        self._init_widgets()

        self.selected_ins.am_subscribe(self._subscribe_select_ins)
        self.poi_trace.am_subscribe(self._subscribe_set_trace)
        self.multi_poi.am_subscribe(self._subscribe_add_poi)

        self.multiPOIList.cellDoubleClicked.connect(self._on_cell_double_click)
        self.multiPOIList.itemChanged.connect(self._on_diagnose_change)

    #
    # Forwarding properties
    #

    @property
    def disasm_view(self):
        """
        Get the current disassembly view (if there is one), or create a new one as needed.
        """
        view = self.workspace.view_manager.current_view_in_category("disassembly")
        if view is None:
            view = self.workspace._get_or_create_disassembly_view()
        return view

    @property
    def poi_trace(self):
        return self.workspace.instance.poi_trace

    @property
    def multi_poi(self):
        return self.workspace.instance.multi_poi

    @property
    def selected_ins(self):
        return self.disasm_view.infodock.selected_insns

    def _init_widgets(self):
        _l.debug("QPOI Viewer Initiating")
        self.tabView = QTabWidget() # QGraphicsView()
        self.tabView.setContentsMargins(0, 0, 0, 0)

        #
        # POI trace Tab
        #
        self.POITraceTab = QWidget()
        self.POITraceTab.setContentsMargins(0, 0, 0, 0)
        singleLayout = QVBoxLayout()
        singleLayout.setSpacing(0)
        singleLayout.setContentsMargins(0, 0, 0, 0)

        self.traceView = QGraphicsView()
        self.traceScene = QGraphicsScene()
        self.traceView.setScene(self.traceScene)

        singleLayout.addWidget(self.traceView)
        self.POITraceTab.setLayout(singleLayout)

        #
        # multiPOI Tab
        #
        self.multiPOITab = QMultiPOITab(self)
        # self.multiPOITab = QWidget()
        multiLayout = QVBoxLayout()
        multiLayout.setSpacing(0)
        multiLayout.setContentsMargins(0, 0, 0, 0)

        self.multiPOIList = QTableWidget(0, 4) # row, col
        self.multiPOIList.setHorizontalHeaderItem(0, QTableWidgetItem("ID"))
        self.multiPOIList.setHorizontalHeaderItem(1, QTableWidgetItem("Crash Point"))
        self.multiPOIList.setHorizontalHeaderItem(2, QTableWidgetItem("Tag"))
        self.multiPOIList.setHorizontalHeaderItem(3, QTableWidgetItem("Diagnose"))
        self.multiPOIList.horizontalHeader().setStretchLastSection(True)
        self.multiPOIList.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.multiPOIList.setSelectionBehavior(QAbstractItemView.SelectRows)
        multiLayout.addWidget(self.multiPOIList)
        self.multiPOITab.setLayout(multiLayout)

        self.tabView.addTab(self.multiPOITab, "POI List")
        self.tabView.addTab(self.POITraceTab, "POI Trace")

        self.POI_TRACE = 1
        self.MULTI_POI = 0

        layout = QVBoxLayout()
        layout.addWidget(self.tabView)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)
        self.show()

    def _reset(self):
        self.traceScene.clear() #clear items
        self.mark = None

        self.legend = None
        self.legend_height = 0

        self.trace_func = QGraphicsItemGroup()
        self.trace_id = QGraphicsItemGroup()
        self.traceScene.addItem(self.trace_func)
        self.hide()

    #
    # Event
    #

    def _on_cell_double_click(self, row, _):
        _l.debug("row %d is double clicked", row)
        first_cell = self.multiPOIList.item(row, 0)
        if first_cell is None:
            return
        poi_id = first_cell.text()
        poi = self.multi_poi.am_obj.get_poi_by_id(poi_id)
        if poi is None:
            return
        # sanity checks
        if not isinstance(poi, dict):
            return
        if 'output' not in poi or not isinstance(poi['output'], dict):
            return
        if 'bbl_history' not in poi['output']:
            return

        trace = poi['output']['bbl_history']
        if self._selected_poi != poi_id and trace is not None:
            # render the trace
            self.poi_trace.am_obj = TraceStatistics(self.workspace, trace, trace_id=poi_id)

            # show the trace statistic in POI trace
            self.poi_trace.am_event()

            # show covered basic blocks and functions
            self.multi_poi.am_obj.reload_heatmap(poi_id)

            # redraw function view
            view = self.workspace.view_manager.first_view_in_category('functions')
            if view is not None:
                view.refresh()

            # redraw disassembly view
            view = self.workspace.view_manager.first_view_in_category('disassembly')
            if view is not None:
                view.redraw_current_graph()

        if trace is not None:
            # switch to POI trace tab
            self.tabView.setCurrentIndex(self.POI_TRACE)
        self._selected_poi = poi_id

        second_cell = self.multiPOIList.item(row, 1)
        crash_addr = None
        if second_cell is not None:
            try:
                crash_addr = int(second_cell.text(), 16)
            except ValueError:
                pass
        if crash_addr is not None:
            # show the crashing address
            view = self.workspace.view_manager.first_view_in_category('disassembly')
            if view is not None:
                crash_func = self._get_func_from_addr(crash_addr)
                if crash_func is not None:
                    self.workspace.on_function_selected(crash_func)
                    self.selected_ins.clear()
                    self.selected_ins.update([crash_addr])
                    self.selected_ins.am_event()
                    view.current_graph.show_instruction(crash_addr)

    def _on_diagnose_change(self, item: QTableWidgetItem):
        column = item.column()
        row = item.row()

        poi_id = self.multiPOIList.item(row, self.POIID_COLUMN).text()
        content = item.text()
        original_content = self.multi_poi.am_obj.get_content_by_id_column(poi_id, column)
        _l.debug('updaing %s, content: %s, original: %s', poi_id, content, original_content)
        if not self._is_identical(content, original_content):
            updated_poi = self.multi_poi.update_poi(poi_id, column, content)
            self._diagnose_handler.submit_updated_poi(poi_id, updated_poi)

    def _subscribe_add_poi(self):
        _l.debug('add a poi to multi poi list')
        if self.multi_poi.am_none:
            self.multi_poi.am_obj = MultiPOI(self.workspace)
        poi_ids = self.multi_poi.am_obj.get_all_poi_ids()

        self.multiPOIList.clearContents()
        self._populate_poi_table(self.multiPOIList, poi_ids)
        self.show()

    def _subscribe_set_trace(self):
        _l.debug('on set trace in poi trace viewer')
        self._reset()
        if self.poi_trace.am_none:
            return
        _l.debug('minheight: %d, count: %d', self.TRACE_FUNC_MINHEIGHT,
                self.poi_trace.count)
        if self.poi_trace.count <= 0:
            _l.warning("No valid addresses found in trace to show. Check base address offsets?")
            self.poi_trace.am_obj = None
            self.poi_trace.am_event()
            return
        if self.TRACE_FUNC_MINHEIGHT < self.poi_trace.count * 15:
            self.trace_func_unit_height = 15
            show_func_tag = True
        else:
            self.trace_func_unit_height = self.TRACE_FUNC_MINHEIGHT / self.poi_trace.count
            show_func_tag = True

        self.legend_height = int(self.poi_trace.count * self.trace_func_unit_height)

        self._show_trace_func(show_func_tag)
        self._show_legend()
        self._set_mark_color()
        self._refresh_multi_list()

        # boundingSize = self.traceScene.itemsBoundingRect().width()
        # windowSize = boundingSize
        # if boundingSize > self.MAX_WINDOW_SIZE:
        #     windowSize = self.MAX_WINDOW_SIZE
        # self.traceScene.setSceneRect(self.traceScene.itemsBoundingRect()) #resize
        # if windowSize > self.width():
        #     self.setMinimumWidth(windowSize)

        self.show()

    def _subscribe_select_ins(self, **kwargs): # pylint: disable=unused-argument
        if self.poi_trace.am_none:
            return

        if self.mark is not None:
            for i in self.mark.childItems():
                self.mark.removeFromGroup(i)
                self.traceScene.removeItem(i)
            self.traceScene.removeItem(self.mark)

        self.mark = QGraphicsItemGroup()
        self.traceScene.addItem(self.mark)

        if self.selected_ins:
            addr = next(iter(self.selected_ins))
            positions = self.poi_trace.get_positions(addr)
            if positions: #if addr is in list of positions
                # handle case where insn was selected from disas view
                if not self._use_precise_position:
                    self.curr_position = positions[0] - self.poi_trace.count
                for p in positions:
                    color = self._get_mark_color(p, self.poi_trace.count)
                    y = self._get_mark_y(p)

                    if p == self.poi_trace.count + self.curr_position: #add thicker line for 'current' mark
                        self.mark.addToGroup(self.traceScene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                                                     self.MARK_HEIGHT*4,
                                                                     QPen(QColor('black')), QBrush(color)))
                    else:
                        self.mark.addToGroup(self.traceScene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                                                     self.MARK_HEIGHT, QPen(color), QBrush(color)))

                self.traceScene.update() #force redraw of the traceScene
                self.scroll_to_position(self.curr_position)

    def _get_func_from_addr(self, addr):
        if self.workspace.instance.cfg.am_none:
            return None
        bbl = self.workspace.instance.cfg.get_any_node(addr, anyaddr=True)
        function_addr = bbl.function_address
        return self.workspace.instance.project.kb.functions.get(function_addr)

    def _populate_poi_table(self, view, poi_ids):
        view.clearContents()
        view.setRowCount(len(poi_ids))
        row = 0 #start after label row
        for poi_id in poi_ids:
            poi = self.multi_poi.am_obj.get_poi_by_id(poi_id)
            _l.debug('populating poi: %s', poi)
            category = poi['category']
            output = poi['output']
            crash_addr = output['bbl']
            if crash_addr is not None:
                crash = hex(crash_addr)
            else:
                crash = None
            diagnose = output.get('diagnose')
            _l.debug('poi_ids: %s', poi_ids)
            _l.debug('current poi id: %s', poi_id)
            self._set_item(view, row, self.POIID_COLUMN, poi_id, editable=False)
            self._set_item(view, row, self.CRASH_COLUMN, crash, editable=True)
            self._set_item(view, row, self.CATEGORY_COLUMN, category, editable=True)
            self._set_item(view, row, self.DIAGNOSE_COLUMN, diagnose, editable=True)
            row += 1
            _l.debug('poi_ids: %s', poi_ids)

    @staticmethod
    def _set_item(view, row, column, text, editable=True):
        if not text:
            text = ""
        item = QTableWidgetItem(text)
        if not editable:
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
        view.setItem(row, column, item)

    def _refresh_multi_list(self):
        multiPOI = self.multi_poi.am_obj
        trace_ids = multiPOI.get_all_poi_ids()

        self.multiPOIList.clearContents()
        self._populate_poi_table(self.multiPOIList, trace_ids)
        if self._selected_traces and self.multiPOIList.rowCount() > 0:
            self.multiPOIList.item(0, 0).setSelected(True)
            self.multiPOIList.item(0, 1).setSelected(True)
        else:
            for row in range(self.multiPOIList.rowCount()):
                item = self.multiPOIList.item(row, 0)
                inputItem = self.multiPOIList.item(row, 1)
                if item.text() in self._selected_traces:
                    item.setSelected(True)
                    inputItem.setSelected(True)
        self.multi_poi.am_event()

    def _on_tab_change(self):
        multiPOI = self.multi_poi.am_obj
        if self.tabView.currentIndex() == self.MULTI_POI:
            multiPOI.is_active_tab = True
            self._refresh_multi_list()
        elif self.tabView.currentIndex() == self.POI_TRACE:
            multiPOI = self.multi_poi.am_obj
            multiPOI.is_active_tab = False
            # self._show_trace_ids()

    def scroll_to_position(self, position):
        relative_pos = self.poi_trace.count + position
        y_offset = self._get_mark_y(relative_pos)

        scrollValue = 0
        if y_offset > 0.5 * self.traceView.size().height():
            scrollValue = y_offset - 0.5 * self.traceView.size().height()
        scrollValue = min(scrollValue, self.traceView.verticalScrollBar().maximum())
        self.traceView.verticalScrollBar().setValue(scrollValue)
        self._use_precise_position = False

    def jump_next_insn(self):
        # for some reason indexing is done backwards
        if self.curr_position + self.poi_trace.count < self.poi_trace.count - 1:
            self.curr_position += 1
            self._use_precise_position = True
            bbl_addr = self.poi_trace.get_bbl_from_position(self.curr_position)
            func = self.poi_trace.get_func_from_position(self.curr_position)
            self._jump_bbl(func, bbl_addr)

    def jump_prev_insn(self):
        if self.curr_position + self.poi_trace.count > 0:
            self.curr_position -= 1
            self._use_precise_position = True
            bbl_addr = self.poi_trace.get_bbl_from_position(self.curr_position)
            func = self.poi_trace.get_func_from_position(self.curr_position)
            self._jump_bbl(func, bbl_addr)

    def mousePressEvent(self, event):
        button = event.button()
        pos = self._to_logical_pos(event.pos())
        if button == Qt.LeftButton and self.tabView.currentIndex() == self.POI_TRACE and self._at_legend(pos):
            func = self._get_func_from_y(pos.y())
            bbl_addr = self._get_bbl_from_y(pos.y())
            self._use_precise_position = True
            self.curr_position = self._get_position(pos.y())
            self._jump_bbl(func, bbl_addr)

    def _jump_bbl(self, func, bbl_addr):
        disasm_view = self.disasm_view
        if disasm_view is not None:
            all_insn_addrs = self.workspace.instance.project.factory.block(bbl_addr).instruction_addrs
            # TODO: replace this with am_events perhaps?
            self.workspace.on_function_selected(func)
            self.selected_ins.clear()
            self.selected_ins.update(all_insn_addrs)
            self.selected_ins.am_event()
            # TODO: this ought to happen automatically as a result of the am_event
            disasm_view.current_graph.show_instruction(bbl_addr)

    def _get_mark_color(self, i, total):
        relative_gradient_pos = i * 1000 // total
        return self.legend_img.pixelColor(self.LEGEND_WIDTH // 2,
                                          relative_gradient_pos)

    def _get_mark_y(self, i):
        return self.TRACE_FUNC_Y + self.trace_func_unit_height * i

    def _show_trace_func(self, show_func_tag=True):
        x = self.TRACE_FUNC_X
        y = self.TRACE_FUNC_Y
        prev_name = None
        for position in self.poi_trace.trace_func:
            func_name = position.func_name
            color = self.poi_trace.get_func_color(func_name)
            self.trace_func.addToGroup(self.traceScene.addRect(x, y,
                                                          self.TRACE_FUNC_WIDTH, self.trace_func_unit_height,
                                                          QPen(color), QBrush(color)))
            if show_func_tag is True and func_name != prev_name:
                tag = self.traceScene.addText(func_name, QFont("Source Code Pro", 7))
                tag.setPos(x + self.TRACE_FUNC_WIDTH +
                           self.TAG_SPACING, y -
                           tag.boundingRect().height() // 2)
                self.trace_func.addToGroup(tag)
                anchor = self.traceScene.addLine(
                    self.TRACE_FUNC_X + self.TRACE_FUNC_WIDTH, y,
                    x + self.TRACE_FUNC_WIDTH + self.TAG_SPACING, y)
                self.trace_func.addToGroup(anchor)
                prev_name = func_name
            y += self.trace_func_unit_height

    @staticmethod
    def _make_legend_gradient(x1, y1, x2, y2):
        gradient = QLinearGradient(x1, y1, x2, y2)
        gradient.setColorAt(0.0, Qt.red)
        gradient.setColorAt(0.4, Qt.yellow)
        gradient.setColorAt(0.6, Qt.green)
        gradient.setColorAt(0.8, Qt.blue)
        gradient.setColorAt(1.0, Qt.darkBlue)
        return gradient

    def _show_legend(self):
        pen = QPen(Qt.transparent)

        gradient = self._make_legend_gradient(self.LEGEND_X, self.LEGEND_Y,
                                   self.LEGEND_X, self.LEGEND_Y + self.legend_height)
        brush = QBrush(gradient)
        self.legend = self.traceScene.addRect(self.LEGEND_X, self.LEGEND_Y,
                                         self.LEGEND_WIDTH, self.legend_height, pen, brush)

        reference_gradient = self._make_legend_gradient(0, 0, self.LEGEND_WIDTH, 1000)
        base_img = QImage(self.LEGEND_WIDTH, 1000, QImage.Format.Format_ARGB32)
        p = QPainter(base_img)
        p.fillRect(base_img.rect(),reference_gradient)
        self.legend_img = base_img #reference shade

    def _set_mark_color(self):
        _l.debug('trace count: %d', self.poi_trace.count)
        for p in range(self.poi_trace.count):
            color = self._get_mark_color(p, self.poi_trace.count)
            self.poi_trace.set_mark_color(p, color)

    def _at_legend(self, pos):
        x = pos.x()
        y = pos.y()
        return self.TRACE_FUNC_X + self.LEGEND_X < x < self.traceView.width() and \
           self.TRACE_FUNC_Y < y < self.TRACE_FUNC_Y + self.legend_height

    def _to_logical_pos(self, pos):
        x_offset = self.traceView.horizontalScrollBar().value()
        y_offset = self.traceView.verticalScrollBar().value()
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)

    def _get_position(self, y):
        y_relative = y - self.legend_height - self.TAB_HEADER_SIZE

        return int(y_relative // self.trace_func_unit_height)

    def _get_bbl_from_y(self, y):
        position = self._get_position(y)
        return self.poi_trace.get_bbl_from_position(position)

    def _get_func_from_y(self, y):
        position = self._get_position(y)
        func = self.poi_trace.get_func_from_position(position)
        return func

    #
    # Context Menu
    #

    def menu_add_empty_poi(self):
        _l.debug('adding a new empty poi item')

        if self._diagnose_handler.get_image_id() is None:
            QMessageBox.warning(self.workspace.main_window,
                                "No CHESS target available",
                                "No angr project is loaded, or you did not associate the current project with a CHESS "
                                "target. Please load a binary and associate it with a CHESS target before creating "
                                "POIs.")
            return

        poi_id = str(uuid4())
        if self.multi_poi.am_none:
            self.multi_poi.am_obj = MultiPOI(self.workspace)
        empty_poi = deepcopy(EMPTY_POI)
        self.multi_poi.add_poi(poi_id, empty_poi)
        self.multi_poi.am_event()
        self._diagnose_handler.submit_updated_poi(poi_id, empty_poi)

    def menu_remove_poi(self):
        items = self.multiPOIList.selectedItems()
        row = items.pop().row()
        poi_id = self.multiPOIList.item(row, 0).text()
        _l.debug('removing ID %s', poi_id)
        self.multi_poi.remove_poi(poi_id)
        self.multi_poi.am_event()

    @staticmethod
    def _is_identical(content, original_content):
        if content == original_content:
            return True
        if content == '' and original_content is None:
            return True
        try:
            if int(content, 16) == int(original_content):
                return True
        except (TypeError, ValueError):
            return False
        return False


class QMultiPOITab(QWidget):
    """
    The tab widget for multi POIs
    """
    def __init__(self, poi_view : QPOIViewer):
        super().__init__()
        self.POIView = poi_view

    def contextMenuEvent(self, event:QContextMenuEvent):
        menu = QMenu("", self)
        menu.addAction('Add POI', self.POIView.menu_add_empty_poi)

        remove = menu.addAction('Remove', self.POIView.menu_remove_poi)
        if len(self.POIView.multiPOIList.selectedItems()) == 0:
            remove.setDisabled(True)

        # remove = menu.addAction('Remove both locally and remotely...', self.POIView.menu_remove_poi_remotely)
        # if len(self.POIView.multiPOIList.selectedItems()) == 0:
        #     remove.setDisabled(True)

        menu.exec_(event.globalPos())


class POIView(BaseView):
    """
    The view for displaying POIs.
    """

    def __init__(self, workspace, default_docking_position, diagnose_handler, *args, **kwargs):
        super().__init__('poi', workspace, default_docking_position, *args, **kwargs)

        self.base_caption = "Points of interest"
        self._diagnose_handler = diagnose_handler

        self._poi_viewer: QPOIViewer = None

        self._init_widgets()

        self.width_hint = 250

    def _init_widgets(self):
        self._poi_viewer = QPOIViewer(self.workspace, diagnose_handler=self._diagnose_handler)
        layout = QVBoxLayout()
        layout.addWidget(self._poi_viewer)
        self.setLayout(layout)
