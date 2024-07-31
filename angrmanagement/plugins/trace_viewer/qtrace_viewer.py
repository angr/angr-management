from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QPoint, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QImage, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QGraphicsItemGroup,
    QGraphicsScene,
    QGraphicsView,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(name=__name__)


class QTraceViewer(QWidget):
    """
    Load a basic block trace through json and visualize it in the disassembly
    Ref: https://github.com/angr/angr-management/pull/122
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

    def __init__(self, workspace: Workspace, disasm_view, parent=None) -> None:
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

        self.view = None
        self.traceView = None
        self.traceTab = None
        self.traceScene = None
        self.multiView = None
        self.listView = None
        self.mark = None
        self.curr_position = 0
        self._use_precise_position = False
        self._selected_traces = []

        self._init_widgets()

        self.trace.am_subscribe(self._on_set_trace)
        self.selected_ins.am_subscribe(self._on_select_ins)
        self.traceTab.installEventFilter(self)

    #
    # Forwarding properties
    #

    @property
    def trace(self):
        return self.workspace.main_instance.trace

    @property
    def multi_trace(self):
        return self.workspace.main_instance.multi_trace

    @property
    def selected_ins(self):
        return self.disasm_view.infodock.selected_insns

    def _init_widgets(self) -> None:
        self.view = QTabWidget()  # QGraphicsView()

        self.traceTab = QWidget()
        tracelayout = QVBoxLayout()

        self.traceView = QGraphicsView()
        self.traceScene = QGraphicsScene()
        self.traceView.setScene(self.traceScene)

        self.listView = QTableWidget(0, 2)  # row, col
        self.listView.setHorizontalHeaderItem(0, QTableWidgetItem("Trace ID"))
        self.listView.setHorizontalHeaderItem(1, QTableWidgetItem("Input ID"))
        self.listView.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.listView.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        # self.listView.horizontalHeader().setStretchLastSection(True)
        # self.listView.horizontalHeader().setSectionResizeModel(0, QHeaderView.Stretch)
        self.listView.cellClicked.connect(self._switch_current_trace)

        self.traceSeedButton = QPushButton("View Input Seed")
        self.traceSeedButton.clicked.connect(self._view_input_seed)

        tracelayout.addWidget(self.traceView)
        tracelayout.addWidget(self.listView)
        tracelayout.addWidget(self.traceSeedButton)
        self.traceTab.setLayout(tracelayout)

        self.multiView = QWidget()
        multiLayout = QVBoxLayout()
        self.multiTraceList = QTableWidget(0, 2)  # row, col
        self.multiTraceList.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.multiTraceList.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.multiTraceList.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.multiTraceList.setHorizontalHeaderItem(0, QTableWidgetItem("Trace ID"))
        self.multiTraceList.setHorizontalHeaderItem(1, QTableWidgetItem("Input ID"))
        self.selectMultiTrace = QPushButton("Refresh Heatmap")
        self.selectMultiTrace.clicked.connect(self._refresh_heatmap)
        multiLayout.addWidget(self.multiTraceList)
        multiLayout.addWidget(self.selectMultiTrace)
        self.multiView.setLayout(multiLayout)

        self.view.addTab(self.traceTab, "SingleTrace")
        self.view.addTab(self.multiView, "MultiTrace HeatMap")
        self.SINGLE_TRACE = 0
        self.MULTI_TRACE = 1

        self.view.currentChanged.connect(self._on_tab_change)

        self._reset()

        layout = QVBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(self.view, Qt.AlignmentFlag.AlignLeft)

        self.setLayout(layout)

    def _reset(self) -> None:
        self.traceScene.clear()  # clear items
        self.listView.clearContents()
        self.multiTraceList.clearContents()
        self.mark = None

        self.legend = None
        self.legend_height = 0

        self.trace_func = QGraphicsItemGroup()
        self.trace_id = QGraphicsItemGroup()
        self.traceScene.addItem(self.trace_func)
        self.hide()

    def _view_input_seed(self) -> None:
        current_trace_stats = self.trace.am_obj
        input_id = current_trace_stats.input_id

        inputSeed = self.multi_trace.am_obj.get_input_seed_for_id(input_id)
        msgText = f"{inputSeed}"
        msgDetails = f"Input for [{current_trace_stats.id}]"
        msgbox = QMessageBox()
        msgbox.setWindowTitle("Seed Input")
        msgbox.setDetailedText(msgDetails)
        msgbox.setText(msgText)
        msgbox.setStandardButtons(QMessageBox.StandardButton.Ok)
        msgbox.exec()

    def _switch_current_trace(self, row) -> None:
        if self.listView.rowCount() <= 0:
            return

        current_trace = self.trace.am_obj.id
        new_trace = self.multiTraceList.item(row, 0).text()
        if current_trace == new_trace:
            return

        trace_stats = self.multi_trace.am_obj.get_trace_with_id(new_trace)
        if trace_stats:
            self.trace.am_obj = trace_stats
            self._on_set_trace()

    def _on_set_trace(self) -> None:
        self._reset()
        if self.trace.am_none or self.trace.count is None:
            return

        log.debug("minheight: %d, count: %d", self.TRACE_FUNC_MINHEIGHT, self.trace.count)
        if self.trace.count <= 0:
            log.warning("No valid addresses found in trace to show. Check base address offsets?")
            self.trace.am_obj = None
            self.trace.am_event()
            return
        if self.trace.count * 15 > self.TRACE_FUNC_MINHEIGHT:
            self.trace_func_unit_height = 15
            show_func_tag = True
        else:
            self.trace_func_unit_height = self.TRACE_FUNC_MINHEIGHT / self.trace.count
            show_func_tag = True

        self.legend_height = int(self.trace.count * self.trace_func_unit_height)

        self._show_trace_func(show_func_tag)
        self._show_legend()
        self._show_trace_ids()
        self._set_mark_color()
        self._refresh_multi_list()

        boundingSize = self.traceScene.itemsBoundingRect().width()
        windowSize = boundingSize
        if boundingSize > self.MAX_WINDOW_SIZE:
            windowSize = self.MAX_WINDOW_SIZE
        self.traceScene.setSceneRect(self.traceScene.itemsBoundingRect())  # resize
        self.setFixedWidth(windowSize)

        # self.listScene.setSceneRect(self.listScene.itemsBoundingRect()) #resize
        self.multiView.setFixedWidth(windowSize)
        cellWidth = windowSize // 2
        self.listView.setColumnWidth(0, cellWidth)
        self.listView.setColumnWidth(1, cellWidth)
        self.listView.setFixedHeight(self.multiView.height() // 4)
        self.multiTraceList.setColumnWidth(0, cellWidth)
        self.multiTraceList.setColumnWidth(1, cellWidth)
        self.view.setFixedWidth(windowSize)

        self.show()

    def _populate_trace_table(self, view, trace_ids) -> None:
        numIDs = len(trace_ids)
        view.clearContents()
        view.setRowCount(numIDs)
        for row, traceID in enumerate(trace_ids):
            inputID = self.multi_trace.am_obj.get_input_id_for_trace_id(traceID)
            if inputID is None:
                self.workspace.log(f"No inputID found for trace {traceID}")
            view.setItem(row, 0, QTableWidgetItem(traceID))
            view.setItem(row, 1, QTableWidgetItem(inputID))

    def _refresh_heatmap(self) -> None:
        multiTrace = self.multi_trace.am_obj
        multiTrace.clear_heatmap()
        multiTrace.is_active_tab = True

        selected_items = self.multiTraceList.selectedItems()
        self._selected_traces.clear()
        for row in range(self.multiTraceList.rowCount()):
            item = self.multiTraceList.item(row, 0)
            if item in selected_items:
                self._selected_traces.append(item.text())
        multiTrace.reload_heatmap(self._selected_traces)
        self.multi_trace.am_event()

    def _refresh_multi_list(self) -> None:
        multiTrace = self.multi_trace.am_obj
        trace_ids = multiTrace.get_all_trace_ids()

        self.multiTraceList.clearContents()
        self._populate_trace_table(self.multiTraceList, trace_ids)
        if self._selected_traces and self.multiTraceList.rowCount() > 0:
            self.multiTraceList.item(0, 0).setSelected(True)
            self.multiTraceList.item(0, 1).setSelected(True)
        else:
            for row in range(self.multiTraceList.rowCount()):
                item = self.multiTraceList.item(row, 0)
                inputItem = self.multiTraceList.item(row, 1)
                if item.text() in self._selected_traces:
                    item.setSelected(True)
                    inputItem.setSelected(True)
        self.multi_trace.am_event()

    def _on_tab_change(self) -> None:
        # self._reset()
        multiTrace = self.multi_trace.am_obj
        if self.view.currentIndex() == self.MULTI_TRACE:
            multiTrace.is_active_tab = True
            self._refresh_multi_list()
        elif self.view.currentIndex() == self.SINGLE_TRACE:
            multiTrace = self.multi_trace.am_obj
            multiTrace.is_active_tab = False
            self._show_trace_ids()

    def _on_select_ins(self, **kwargs) -> None:  # pylint: disable=unused-argument
        if self.trace.am_none:
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
            positions = self.trace.get_positions(addr)
            if positions:  # if addr is in list of positions
                if not self._use_precise_position:  # handle case where insn was selected from disas view
                    self.curr_position = positions[0] - self.trace.count
                for p in positions:
                    color = self._get_mark_color(p, self.trace.count)
                    y = self._get_mark_y(p)

                    if p == self.trace.count + self.curr_position:  # add thicker line for 'current' mark
                        self.mark.addToGroup(
                            self.traceScene.addRect(
                                self.MARK_X,
                                y,
                                self.MARK_WIDTH,
                                self.MARK_HEIGHT * 4,
                                QPen(QColor("black")),
                                QBrush(color),
                            )
                        )
                    else:
                        self.mark.addToGroup(
                            self.traceScene.addRect(
                                self.MARK_X, y, self.MARK_WIDTH, self.MARK_HEIGHT, QPen(color), QBrush(color)
                            )
                        )

                self.traceScene.update()  # force redraw of the traceScene
                self.scroll_to_position(self.curr_position)

    def scroll_to_position(self, position) -> None:
        relative_pos = self.trace.count + position
        y_offset = self._get_mark_y(relative_pos)

        scrollValue = 0
        if y_offset > 0.5 * self.traceView.size().height():
            scrollValue = y_offset - 0.5 * self.traceView.size().height()
        scrollValue = min(scrollValue, self.traceView.verticalScrollBar().maximum())
        self.traceView.verticalScrollBar().setValue(scrollValue)
        self._use_precise_position = False

    def jump_next_insn(self) -> None:
        if self.curr_position + self.trace.count < self.trace.count - 1:  # for some reason indexing is done backwards
            self.curr_position += 1
            self._use_precise_position = True
            bbl_addr = self.trace.get_bbl_from_position(self.curr_position)
            func = self.trace.get_func_from_position(self.curr_position)
            self._jump_bbl(func, bbl_addr)

    def jump_prev_insn(self) -> None:
        if self.curr_position + self.trace.count > 0:
            self.curr_position -= 1
            self._use_precise_position = True
            bbl_addr = self.trace.get_bbl_from_position(self.curr_position)
            func = self.trace.get_func_from_position(self.curr_position)
            self._jump_bbl(func, bbl_addr)

    def eventFilter(self, obj, event) -> bool:  # specifically to catch arrow keys #pylint: disable=unused-argument
        # more elegant solution to link w/ self.view's scroll bar keypressevent?
        if event.type() == QEvent.Type.KeyPress:
            if not event.modifiers() & Qt.KeyboardModifier.ShiftModifier:  # shift + arrowkeys
                return False
            key = event.key()
            if key in [Qt.Key.Key_Up, Qt.Key.Key_Left]:
                self.jump_prev_insn()
            elif key in [Qt.Key.Key_Down, Qt.Key.Key_Right]:
                self.jump_next_insn()
            return True

        return False  # pass through all other events

    def mousePressEvent(self, event) -> None:
        button = event.button()
        pos = self._to_logical_pos(event.pos())
        if (
            button == Qt.MouseButton.LeftButton
            and self.view.currentIndex() == self.SINGLE_TRACE
            and self._at_legend(pos)
        ):
            func = self._get_func_from_y(pos.y())
            bbl_addr = self._get_bbl_from_y(pos.y())
            self._use_precise_position = True
            self.curr_position = self._get_position(pos.y())
            self._jump_bbl(func, bbl_addr)

    def _jump_bbl(self, func, bbl_addr) -> None:
        all_insn_addrs = self.workspace.main_instance.project.factory.block(bbl_addr).instruction_addrs
        # TODO: replace this with am_events perhaps?
        if func is None:
            return
        self.workspace.on_function_selected(func)
        self.selected_ins.clear()
        self.selected_ins.update(all_insn_addrs)
        self.selected_ins.am_event()
        # TODO: this ought to happen automatically as a result of the am_event
        self.disasm_view.current_graph.show_instruction(bbl_addr)

    def _get_mark_color(self, i, total: int):
        relative_gradient_pos = i * 1000 // total
        return self.legend_img.pixelColor(self.LEGEND_WIDTH // 2, relative_gradient_pos)

    def _get_mark_y(self, i):
        return self.TRACE_FUNC_Y + self.trace_func_unit_height * i

    def _show_trace_ids(self) -> None:
        trace_ids = self.multi_trace.get_all_trace_ids()
        # traceID = self.listScene.addText(id_txt, QFont("Source Code Pro", 7))
        # traceID.setPos(5,5)
        self.listView.clearContents()
        self._populate_trace_table(self.listView, trace_ids)
        if len(self.listView.selectedItems()) <= 0 and not self.trace.am_none:
            for row in range(self.listView.rowCount()):
                item = self.listView.item(row, 0)
                inputItem = self.listView.item(row, 1)
                if self.trace.id in item.text():
                    item.setSelected(True)
                    inputItem.setSelected(True)
                    break

    def _show_trace_func(self, show_func_tag) -> None:
        x = self.TRACE_FUNC_X
        y = self.TRACE_FUNC_Y
        prev_name = None
        for position in self.trace.trace_func:
            bbl_addr = position.bbl_addr
            func_name = position.func_name
            log.debug("Draw function %x, %s", bbl_addr, func_name)
            color = self.trace.get_func_color(func_name)
            self.trace_func.addToGroup(
                self.traceScene.addRect(
                    x, y, self.TRACE_FUNC_WIDTH, self.trace_func_unit_height, QPen(color), QBrush(color)
                )
            )
            if show_func_tag is True and func_name != prev_name:
                tag = self.traceScene.addText(func_name, QFont("Source Code Pro", 7))
                tag.setPos(x + self.TRACE_FUNC_WIDTH + self.TAG_SPACING, y - tag.boundingRect().height() // 2)
                self.trace_func.addToGroup(tag)
                anchor = self.traceScene.addLine(
                    self.TRACE_FUNC_X + self.TRACE_FUNC_WIDTH, y, x + self.TRACE_FUNC_WIDTH + self.TAG_SPACING, y
                )
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

    def _show_legend(self) -> None:
        pen = QPen(Qt.GlobalColor.transparent)

        gradient = self._make_legend_gradient(
            self.LEGEND_X, self.LEGEND_Y, self.LEGEND_X, self.LEGEND_Y + self.legend_height
        )
        brush = QBrush(gradient)
        self.legend = self.traceScene.addRect(
            self.LEGEND_X, self.LEGEND_Y, self.LEGEND_WIDTH, self.legend_height, pen, brush
        )

        reference_gradient = self._make_legend_gradient(0, 0, self.LEGEND_WIDTH, 1000)
        base_img = QImage(self.LEGEND_WIDTH, 1000, QImage.Format.Format_ARGB32)
        p = QPainter(base_img)
        p.fillRect(base_img.rect(), reference_gradient)
        self.legend_img = base_img  # reference shade

    def _set_mark_color(self) -> None:
        for p in range(self.trace.count):
            color = self._get_mark_color(p, self.trace.count)
            self.trace.set_mark_color(p, color)

    def _at_legend(self, pos):
        x = pos.x()
        y = pos.y()
        return (
            self.TRACE_FUNC_X + self.LEGEND_X < x < self.traceView.width()
            and self.TRACE_FUNC_Y < y < self.TRACE_FUNC_Y + self.legend_height
        )

    def _to_logical_pos(self, pos):
        x_offset = self.traceView.horizontalScrollBar().value()
        y_offset = self.traceView.verticalScrollBar().value()
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)

    def _get_position(self, y):
        y_relative = y - self.legend_height - self.TAB_HEADER_SIZE

        return int(y_relative // self.trace_func_unit_height)

    def _get_bbl_from_y(self, y):
        position = self._get_position(y)
        return self.trace.get_bbl_from_position(position)

    def _get_func_from_y(self, y):
        position = self._get_position(y)
        func = self.trace.get_func_from_position(position)
        return func
