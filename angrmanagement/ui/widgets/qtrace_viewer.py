from PySide2.QtWidgets import QWidget, QHBoxLayout, QGraphicsScene, QGraphicsView, QGraphicsItemGroup
from PySide2.QtGui import QPen, QBrush, QLinearGradient, QPixmap, QColor, QPainter, QFont, QImage
from PySide2.QtCore import Qt, QRectF, QSize, QPoint

from ...config import Conf

import logging
l = logging.getLogger(name=__name__)

class QTraceViewer(QWidget):
    TAG_SPACING = 50
    LEGEND_X = -50
    LEGEND_Y = 0
    LEGEND_WIDTH = 10

    TRACE_FUNC_X = 0
    TRACE_FUNC_Y = 0
    TRACE_FUNC_WIDTH = 50
    TRACE_FUNC_MINHEIGHT = 1000

    MARK_X = LEGEND_X
    MARK_WIDTH = TRACE_FUNC_X - LEGEND_X + TRACE_FUNC_WIDTH
    MARK_HEIGHT = 1

    def __init__(self, workspace, disasm_view, parent=None):
        super().__init__(parent=parent)
        self.workspace = workspace
        self.disasm_view = disasm_view

        self.view = None
        self.scene = None
        self.mark = None

        self._trace = None
        self.selected_ins = None

        self._init_widgets()

    def _init_widgets(self):
        self.view = QGraphicsView()
        self.scene = QGraphicsScene()
        self.view.setScene(self.scene)

        self.trace_func = QGraphicsItemGroup()
        self.scene.addItem(self.trace_func)

        self.legend = None

        layout = QHBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.setAlignment(self.view, Qt.AlignLeft)

        self.setLayout(layout)
        #self.setFixedWidth(400)

    def set_trace(self, trace):
        self._trace = trace
        l.debug('minheight: %d, count: %d', self.TRACE_FUNC_MINHEIGHT,
                self._trace.count)
        if(self._trace.count <= 0):
            l.warn("No valid addresses found in trace to show. Check base address offsets?")
            return
        if self.TRACE_FUNC_MINHEIGHT < self._trace.count * 15:
            self.trace_func_unit_height = 15
            show_func_tag = True
        else:
            self.trace_func_unit_height = self.TRACE_FUNC_MINHEIGHT / self._trace.count
            show_func_tag = True

        self.legend_height = int(self._trace.count * self.trace_func_unit_height)

        self._show_trace_func(show_func_tag)
        self._show_legend()
        self._set_mark_color()

        # if self.selected_ins is not None:
        #     self.set_trace_mark(self.selected_ins)

    def set_trace_mark(self, addr):
        self.selected_ins = addr
        if self.mark is not None:
            for i in self.mark.childItems():
                self.mark.removeFromGroup(i)
                self.scene.removeItem(i)
        else:
            self.mark = QGraphicsItemGroup()
            self.scene.addItem(self.mark)
        positions = self._trace.get_positions(addr)
        for p in positions:
            color = self._get_mark_color(p, self._trace.count)
            y = self._get_mark_y(p, self._trace.count)
            self.mark.addToGroup(self.scene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                                    self.MARK_HEIGHT, QPen(color), QBrush(color)))

        y = self._get_mark_y(positions[0], self._trace.count)
        self.view.verticalScrollBar().setValue(y - 0.5 * self.view.size().height())

    def mousePressEvent(self, event):
        button = event.button()
        pos = self._to_logical_pos(event.pos())
        if button == Qt.LeftButton and self._at_legend(pos):
            func = self._get_func_from_y(pos.y())
            bbl_addr = self._get_bbl_from_y(pos.y())
            self.workspace.on_function_selected(func)
            self.disasm_view.infodock.toggle_instruction_selection(bbl_addr)

    def _get_mark_color(self, i, total):
        relative_gradient_pos = i * 1000 // total
        return self.legend_img.pixelColor(self.LEGEND_WIDTH // 2,
                                          relative_gradient_pos)

    def _get_mark_y(self, i, total):
        return self.TRACE_FUNC_Y + self.trace_func_unit_height * i

    def _show_trace_func(self, show_func_tag):
        x = self.TRACE_FUNC_X
        y = self.TRACE_FUNC_Y
        prev_name = None
        for position in self._trace.trace_func:
            bbl_addr = position.bbl_addr
            func_name = position.func_name
            l.debug('Draw function %x, %s', bbl_addr, func_name)
            color = self._trace.get_func_color(func_name)
            self.trace_func.addToGroup(self.scene.addRect(x, y,
                                                          self.TRACE_FUNC_WIDTH, self.trace_func_unit_height,
                                                          QPen(color), QBrush(color)))
            if show_func_tag is True and func_name != prev_name:
                tag = self.scene.addText(func_name,
                                         Conf.trace_func_font)
                tag.setPos(x + self.TRACE_FUNC_WIDTH +
                           self.TAG_SPACING, y -
                           tag.boundingRect().height() // 2)
                self.trace_func.addToGroup(tag)
                anchor = self.scene.addLine(
                    self.TRACE_FUNC_X + self.TRACE_FUNC_WIDTH, y,
                    x + self.TRACE_FUNC_WIDTH + self.TAG_SPACING, y)
                self.trace_func.addToGroup(anchor)
                prev_name = func_name
            y += self.trace_func_unit_height

    def _make_legend_gradient(self, x1, y1, x2, y2):
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
        self.legend = self.scene.addRect(self.LEGEND_X, self.LEGEND_Y,
                                         self.LEGEND_WIDTH, self.legend_height, pen, brush)

        reference_gradient = self._make_legend_gradient(0, 0, self.LEGEND_WIDTH, 1000)
        base_img = QImage(self.LEGEND_WIDTH, 1000, QImage.Format.Format_ARGB32)
        p = QPainter(base_img)
        p.fillRect(base_img.rect(),reference_gradient);
        self.legend_img = base_img #reference shade

    def _set_mark_color(self):
        for p in range(self._trace.count):
            color = self._get_mark_color(p, self._trace.count)
            self._trace.set_mark_color(p, color)

    def _at_legend(self, pos):
        x = pos.x()
        y = pos.y()
        if x > self.TRACE_FUNC_X + self.LEGEND_X and \
                x < self.view.width() and \
                y > self.TRACE_FUNC_Y and \
                y < self.TRACE_FUNC_Y + self.legend_height:
            return True
        else:
            return False

    def _to_logical_pos(self, pos):
        x_offset = self.view.horizontalScrollBar().value()
        y_offset = self.view.verticalScrollBar().value()
        qpos = QPoint(pos.x() + x_offset, pos.y() + y_offset)
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)

    def _get_position(self, y):
        y_relative = y - self.legend_height

        return int(y_relative // self.trace_func_unit_height)

    def _get_bbl_from_y(self, y):
        position = self._get_position(y)
        return self._trace.get_bbl_from_position(position)

    def _get_func_from_y(self, y):
        position = self._get_position(y)
        func_name = self._trace.get_func_name_from_position(position)
        return self.workspace.instance.cfg.kb.functions.function(name=func_name)
