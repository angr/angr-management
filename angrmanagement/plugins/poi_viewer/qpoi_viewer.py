import logging
from PySide2.QtWidgets import QWidget, QVBoxLayout, QGraphicsScene, QGraphicsView, QGraphicsItemGroup
from PySide2.QtWidgets import QTabWidget, QPushButton, QAbstractItemView
from PySide2.QtWidgets import  QMessageBox, QInputDialog, QTableWidget, QTableWidgetItem, QLineEdit, QHeaderView
from PySide2.QtGui import QPen, QBrush, QLinearGradient, QColor, QPainter, QImage, QFont
from PySide2.QtCore import Qt, QPoint, QEvent
from .trace_statistics import TraceStatistics
from .multi_poi import MultiPOI

_l = logging.getLogger(name=__name__)
_l.setLevel('DEBUG')


class QPOIViewer(QWidget):

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

    def __init__(self, workspace, disasm_view, parent=None):
        super().__init__(parent=parent)
        self.workspace = workspace
        self.disasm_view = disasm_view

        self.mark = None
        self.legend = None
        self.legend_height = 0
        self.legend_img = None
        self.trace_func_unit_height = 0

        self.trace_func = None
        self.trace_id = None

        self.tabView = None
        self.traceView = None
        self.singlePOI = None
        self.traceScene = None
        self.multiPOI = None

        self.mark = None
        self.curr_position = 0
        self._use_precise_position = False
        self._selected_traces = []

        self._init_widgets()

        self.poi_trace.am_subscribe(self._subscribe_set_trace)
        # self.selected_ins.am_subscribe(self._on_select_ins)
        self.singlePOI.installEventFilter(self)

        self.multi_poi.am_subscribe(self._subscribe_add_poi)
    #
    # Forwarding properties
    #

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
        self.tabView.setMinimumWidth(self.parent().width())
        self.tabView.setContentsMargins(0, 0, 0, 0)
        #
        # singlePOI Tab
        #
        self.singlePOI = QWidget()
        self.singlePOI.setContentsMargins(0, 0, 0, 0)
        self.singlePOI.setMinimumWidth(self.parent().width())
        singleLayout = QVBoxLayout()
        singleLayout.setSpacing(0)
        singleLayout.setContentsMargins(0, 0, 0, 0)

        self.traceView = QGraphicsView()
        self.traceScene = QGraphicsScene()
        self.traceView.setScene(self.traceScene)

        singleLayout.addWidget(self.traceView)
        self.singlePOI.setLayout(singleLayout)

        #
        # multiPOI Tab
        #
        self.multiPOI = QWidget()
        self.multiPOI.setMinimumWidth(self.parent().width())
        multiLayout = QVBoxLayout()
        multiLayout.setSpacing(0)
        multiLayout.setContentsMargins(0, 0, 0, 0)
        self.multiPOIList = QTableWidget(0, 4) # row, col
        self.multiPOIList.setMinimumWidth(self.parent().width())
        self.multiPOIList.setHorizontalHeaderItem(0, QTableWidgetItem("ID"))
        self.multiPOIList.setHorizontalHeaderItem(1, QTableWidgetItem("Crash Point"))
        self.multiPOIList.setHorizontalHeaderItem(2, QTableWidgetItem("Tag"))
        self.multiPOIList.setHorizontalHeaderItem(3, QTableWidgetItem("Diagnose"))
        self.multiPOIList.horizontalHeader().setStretchLastSection(True)
        self.multiPOIList.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.multiPOIList.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.multiPOIList.cellDoubleClicked.connect(self._on_cell_double_click)
        multiLayout.addWidget(self.multiPOIList)
        self.multiPOI.setLayout(multiLayout)

        self.tabView.addTab(self.multiPOI, "POI List")
        self.tabView.addTab(self.singlePOI, "POI Trace")

        self.SINGLE_TRACE = 1
        self.MULTI_TRACE = 0

        # self.view.currentChanged.connect(self._on_tab_change)

        # self._reset()

        layout = QVBoxLayout()
        layout.addWidget(self.tabView)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.setAlignment(self.tabView, Qt.AlignLeft)

        self.setLayout(layout)
        self.show()

    def _reset(self):
        self.traceScene.clear() #clear items
        # self.listView.clearContents()
        # self.multiTraceList.clearContents()
        self.mark = None

        self.legend = None
        self.legend_height = 0

        self.trace_func = QGraphicsItemGroup()
        self.trace_id = QGraphicsItemGroup()
        self.traceScene.addItem(self.trace_func)
        self.hide()


    # def _switch_current_trace(self, row):
    #     if self.listView.rowCount() <= 0:
    #         return
    #
    #     current_trace = self.poi_trace.am_obj.id
    #     new_trace = self.multiPOIList.item(row, 0).text()
    #     if current_trace == new_trace:
    #         return
    #
    #     trace_stats = self.multi_poi.am_obj.get_trace_with_id(new_trace)
    #     if trace_stats:
    #         self.poi_trace.am_obj = trace_stats
    #         self._subscribe_set_trace()


    # Callback

    def _on_cell_double_click(self, row, column):
        _l.debug("row %d is clicked!", row)
        poi_id = int(self.multiPOIList.item(row, 0).text())
        if self.poi_trace.am_none:
            self.poi_trace.am_obj = TraceStatistics(self.workspace, self.multi_poi.am_obj.get_poi_by_id(poi_id))

        # show the trace statistic in POI trace
        self.poi_trace.am_event(poi_id=poi_id)

        # show covered basic blocks and functions
        self.multi_poi.am_obj.reload_heatmap(poi_id)
        view = self.workspace.view_manager.first_view_in_category('functions')
        if view is not None:
            view.refresh()
        # view = self.workspace.view_manager.first_view_in_category('disassembly')
        # if view is not None:
        #     view.redraw_current_graph()

        self.tabView.setCurrentIndex(self.SINGLE_TRACE)
        # self.multi_poi.am_event()


    def _subscribe_add_poi(self, **kwargs):
        _l.debug('add a poi to multi poi list')
        if self.multi_poi.am_none:
            self.multi_poi.am_obj = MultiPOI(self.workspace)
        multiPOI = self.multi_poi.am_obj
        poi_ids = multiPOI.get_all_poi_ids()

        self.multiPOIList.clearContents()
        self._populate_poi_table(self.multiPOIList, poi_ids)
        self.show()
        # if self._selected_traces and self.multiTraceList.rowCount() > 0:
        #     self.multiTraceList.item(0,0).setSelected(True)
        #     self.multiTraceList.item(0,1).setSelected(True)
        # else:
        #     for row in range(self.multiTraceList.rowCount()):
        #         item = self.multiTraceList.item(row, 0)
        #         inputItem = self.multiTraceList.item(row, 1)
        #         if item.text() in self._selected_traces:
        #             item.setSelected(True)
        #             inputItem.setSelected(True)
        # self.multi_poi.am_event()


    def _subscribe_set_trace(self, **kwargs):
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
        self._show_trace_ids()
        self._set_mark_color()
        self._refresh_multi_list()

        boundingSize = self.traceScene.itemsBoundingRect().width()
        windowSize = boundingSize
        if boundingSize > self.MAX_WINDOW_SIZE:
            windowSize = self.MAX_WINDOW_SIZE
        self.traceScene.setSceneRect(self.traceScene.itemsBoundingRect()) #resize
        # self.setFixedWidth(windowSize)

        # self.listScene.setSceneRect(self.listScene.itemsBoundingRect()) #resize
        # self.multiPOI.setFixedWidth(windowSize)
        cellWidth = windowSize // 2
        # self.listView.setColumnWidth(0, cellWidth)
        # self.listView.setColumnWidth(1, cellWidth)
        # self.listView.setFixedHeight(self.multiPOI.height() // 4)
        # self.multiTraceList.setColumnWidth(0, cellWidth)
        # self.multiTraceList.setColumnWidth(1, cellWidth)
        # self.tabview.setFixedWidth(windowSize)

        self.show()

    def _populate_poi_table(self, view, poi_ids):

        view.clearContents()
        view.setRowCount(len(poi_ids))
        row = 0 #start after label row
        for i in poi_ids:
            poi = self.multi_poi.am_obj.get_poi_by_id(i)
            _l.debug("poi %d", i)
            self._set_item(view, row, 0, str(i), editable=False)
            self._set_item(view, row, 1, hex(poi['bbl']), editable=False)
            self._set_item(view, row, 2, poi['tag'], editable=False)
            self._set_item(view, row, 3, poi.get('diagnose', ''), editable=True)
            row += 1

    def _set_item(self, view, row, column, text, editable=True):
        item = QTableWidgetItem(text)
        if not editable:
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
        view.setItem(row, column, item)

    def _refresh_heatmap(self):
        multiPOI = self.multi_poi.am_obj
        multiPOI.clear_heatmap()
        multiPOI.is_active_tab = True

        selected_items = self.multiPOIList.selectedItems()
        self._selected_traces.clear()
        for row in range(self.multiPOIList.rowCount()):
            item = self.multiPOIList.item(row, 0)
            if item in selected_items:
                self._selected_traces.append(item.text())
        multiPOI.reload_heatmap(self._selected_traces)
        self.multi_poi.am_event()

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
        # self._reset()
        multiPOI = self.multi_poi.am_obj
        if self.tabView.currentIndex() == self.MULTI_TRACE:
            multiPOI.is_active_tab = True
            self._refresh_multi_list()
        elif self.tabView.currentIndex() == self.SINGLE_TRACE:
            multiPOI = self.multi_poi.am_obj
            multiPOI.is_active_tab = False
            self._show_trace_ids()

    def _on_select_ins(self, **kwargs): # pylint: disable=unused-argument
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
                if not self._use_precise_position: #handle case where insn was selected from disas view
                    self.curr_position = positions[0] - self.poi_trace.count
                for p in positions:
                    color = self._get_mark_color(p, self.poi_trace.count)
                    y = self._get_mark_y(p)

                    if p == self.poi_trace.count + self.curr_position: #add thicker line for 'current' mark
                        self.mark.addToGroup(self.traceScene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                            self.MARK_HEIGHT*4, QPen(QColor('black')), QBrush(color)))
                    else:
                        self.mark.addToGroup(self.traceScene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                                                self.MARK_HEIGHT, QPen(color), QBrush(color)))

                self.traceScene.update() #force redraw of the traceScene
                self.scroll_to_position(self.curr_position)

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
        if self.curr_position + self.poi_trace.count < self.poi_trace.count - 1: #for some reason indexing is done backwards
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

    def eventFilter(self, obj, event): #specifically to catch arrow keys #pylint: disable=unused-argument
        # more elegant solution to link w/ self.view's scroll bar keypressevent?
        if event.type() == QEvent.Type.KeyPress:
            if not event.modifiers() & Qt.ShiftModifier: #shift + arrowkeys
                return False
            key = event.key()
            if key in [Qt.Key_Up, Qt.Key_Left]:
                self.jump_prev_insn()
            elif key in [Qt.Key_Down, Qt.Key_Right]:
                self.jump_next_insn()
            return True

        return False  # pass through all other events

    def mousePressEvent(self, event):
        _l.debug("press")
        button = event.button()
        pos = self._to_logical_pos(event.pos())
        if button == Qt.LeftButton and self.tabView.currentIndex() == self.SINGLE_TRACE and self._at_legend(pos):
            func = self._get_func_from_y(pos.y())
            bbl_addr = self._get_bbl_from_y(pos.y())
            self._use_precise_position = True
            self.curr_position = self._get_position(pos.y())
            self._jump_bbl(func, bbl_addr)

    def _jump_bbl(self, func, bbl_addr):
        all_insn_addrs = self.workspace.instance.project.factory.block(bbl_addr).instruction_addrs
        # TODO: replace this with am_events perhaps?
        self.workspace.on_function_selected(func)
        self.selected_ins.clear()
        self.selected_ins.update(all_insn_addrs)
        self.selected_ins.am_event()
        # TODO: this ought to happen automatically as a result of the am_event
        self.disasm_view.current_graph.show_instruction(bbl_addr)

    def _get_mark_color(self, i, total):
        relative_gradient_pos = i * 1000 // total
        return self.legend_img.pixelColor(self.LEGEND_WIDTH // 2,
                                          relative_gradient_pos)

    def _get_mark_y(self, i):
        return self.TRACE_FUNC_Y + self.trace_func_unit_height * i


    def _show_trace_ids(self):
        poi_ids = self.multi_poi.get_all_poi_ids()
        # traceID = self.listScene.addText(id_txt, QFont("Source Code Pro", 7))
        # traceID.setPos(5,5)
        # self.listView.clearContents()
        # self._populate_trace_table(self.listView, poi_ids)
        # if len(self.listView.selectedItems()) <= 0 and not self.poi_trace.am_none:
        #     for row in range(self.listView.rowCount()):
        #         item = self.listView.item(row, 0)
        #         inputItem = self.listView.item(row, 1)
        #         if self.poi_trace.id in item.text():
        #             item.setSelected(True)
        #             inputItem.setSelected(True)
        #             break


    def _show_trace_func(self, show_func_tag=True):
        x = self.TRACE_FUNC_X
        y = self.TRACE_FUNC_Y
        prev_name = None
        for position in self.poi_trace.trace_func:
            bbl_addr = position.bbl_addr
            func_name = position.func_name
            _l.debug('Draw function %x, %s', bbl_addr, func_name)
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
