from PySide2.QtWidgets import QWidget, QHBoxLayout, QGraphicsScene, QGraphicsView, QGraphicsItemGroup
from PySide2.QtGui import QPen, QBrush, QLinearGradient, QColor, QPainter, QImage, QFont
from PySide2.QtCore import Qt, QPoint, QEvent

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
        self.curr_position = 0
        self._use_precise_position = False

        self._init_widgets()

        self.trace.am_subscribe(self._on_set_trace)
        self.selected_ins.am_subscribe(self._on_select_ins)
        self.view.installEventFilter(self)

    #
    # Forwarding properties
    #

    @property
    def trace(self):
        return self.workspace.instance.trace

    @property
    def selected_ins(self):
        return self.disasm_view.infodock.selected_insns

    def _init_widgets(self):
        self.view = QGraphicsView()
        self.scene = QGraphicsScene()
        self.view.setScene(self.scene)

        self._reset()

        layout = QHBoxLayout()
        layout.addWidget(self.view)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(self.view, Qt.AlignLeft)

        self.setLayout(layout)

    def _reset(self):
        self.scene.clear() #clear items
        self.mark = None

        self.legend = None
        self.legend_height = 0

        self.trace_func = QGraphicsItemGroup()
        self.scene.addItem(self.trace_func)
        self.hide()

    def _on_set_trace(self, **kwargs):
        self._reset()

        if self.trace.am_obj is not None:
            l.debug('minheight: %d, count: %d', self.TRACE_FUNC_MINHEIGHT,
                    self.trace.count)
            if self.trace.count <= 0:
                l.warning("No valid addresses found in trace to show. Check base address offsets?")
                self.trace.am_obj = None
                self.trace.am_event()
                return
            if self.TRACE_FUNC_MINHEIGHT < self.trace.count * 15:
                self.trace_func_unit_height = 15
                show_func_tag = True
            else:
                self.trace_func_unit_height = self.TRACE_FUNC_MINHEIGHT / self.trace.count
                show_func_tag = True

            self.legend_height = int(self.trace.count * self.trace_func_unit_height)

            self._show_trace_func(show_func_tag)
            self._show_legend()
            self._set_mark_color()

            self.scene.setSceneRect(self.scene.itemsBoundingRect()) #resize
            self.setFixedWidth(self.scene.itemsBoundingRect().width())
            self.view.setFixedWidth(self.scene.itemsBoundingRect().width())

            self.show()

    def _on_select_ins(self, **kwargs):
        if self.trace == None:
            return

        if self.mark is not None:
            for i in self.mark.childItems():
                self.mark.removeFromGroup(i)
                self.scene.removeItem(i)
            self.scene.removeItem(self.mark)

        self.mark = QGraphicsItemGroup()
        self.scene.addItem(self.mark)

        if self.selected_ins:
            addr = next(iter(self.selected_ins))
            positions = self.trace.get_positions(addr)
            if positions: #if addr is in list of positions
                if not self._use_precise_position: #handle case where insn was selected from disas view
                    self.curr_position = positions[0] - self.trace.count
                for p in positions:
                    color = self._get_mark_color(p, self.trace.count)
                    y = self._get_mark_y(p, self.trace.count)

                    if p == self.trace.count + self.curr_position: #add thicker line for 'current' mark
                        self.mark.addToGroup(self.scene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                            self.MARK_HEIGHT*4, QPen(QColor('black')), QBrush(color)))
                    else:
                        self.mark.addToGroup(self.scene.addRect(self.MARK_X, y, self.MARK_WIDTH,
                                                                self.MARK_HEIGHT, QPen(color), QBrush(color)))
                #y = self._get_mark_y(positions[0], self.trace.count)
                #self.view.verticalScrollBar().setValue(y - 0.5 * self.view.size().height())

                self.scene.update() #force redraw of the scene
                self.scroll_to_position(self.curr_position)

    def scroll_to_position(self, position):
        relative_pos = self.trace.count + position
        y_offset = self._get_mark_y(relative_pos, self.trace.count)

        scrollValue = 0
        if y_offset > 0.5 * self.view.size().height():
            scrollValue = y_offset - 0.5 * self.view.size().height()
        scrollValue = min(scrollValue, self.view.verticalScrollBar().maximum())
        self.view.verticalScrollBar().setValue(scrollValue)
        self._use_precise_position = False

    def jump_next_insn(self):
        if self.curr_position + self.trace.count < self.trace.count - 1: #for some reason indexing is done backwards
            self.curr_position += 1
            self._use_precise_position = True
            func_name = self.trace.trace_func[self.curr_position].func_name
            func = self._get_func_from_func_name(func_name)
            bbl_addr = self.trace.trace_func[self.curr_position].bbl_addr
            self._jump_bbl(func, bbl_addr)

    def jump_prev_insn(self):
        if self.curr_position + self.trace.count > 0:
            self.curr_position -= 1
            self._use_precise_position = True
            func_name = self.trace.trace_func[self.curr_position].func_name
            func = self._get_func_from_func_name(func_name)
            bbl_addr = self.trace.trace_func[self.curr_position].bbl_addr
            self._jump_bbl(func, bbl_addr)

    def eventFilter(self, object, event): #specifically to catch arrow keys
        # more elegant solution to link w/ self.view's scroll bar keypressevent?
        if event.type() == QEvent.Type.KeyPress:
            if not (event.modifiers() & Qt.ShiftModifier): #shift + arrowkeys
                return False
            key = event.key()
            if key == Qt.Key_Up or key == Qt.Key_Left:
                self.jump_prev_insn()
            elif key == Qt.Key_Down or key == Qt.Key_Right:
                self.jump_next_insn()
            return True

        return False  # pass through all other events

    def mousePressEvent(self, event):
        button = event.button()
        pos = self._to_logical_pos(event.pos())
        if button == Qt.LeftButton and self._at_legend(pos):
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

    def _get_mark_y(self, i, total):
        return self.TRACE_FUNC_Y + self.trace_func_unit_height * i

    def _show_trace_func(self, show_func_tag):
        x = self.TRACE_FUNC_X
        y = self.TRACE_FUNC_Y
        prev_name = None
        for position in self.trace.trace_func:
            bbl_addr = position.bbl_addr
            func_name = position.func_name
            l.debug('Draw function %x, %s', bbl_addr, func_name)
            color = self.trace.get_func_color(func_name)
            self.trace_func.addToGroup(self.scene.addRect(x, y,
                                                          self.TRACE_FUNC_WIDTH, self.trace_func_unit_height,
                                                          QPen(color), QBrush(color)))
            if show_func_tag is True and func_name != prev_name:
                tag = self.scene.addText(func_name, QFont("Source Code Pro", 7))
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
        p.fillRect(base_img.rect(),reference_gradient)
        self.legend_img = base_img #reference shade


    def _set_mark_color(self):
        for p in range(self.trace.count):
            color = self._get_mark_color(p, self.trace.count)
            self.trace.set_mark_color(p, color)

    def _at_legend(self, pos):
        x = pos.x()
        y = pos.y()
        if self.TRACE_FUNC_X + self.LEGEND_X < x < self.view.width() and \
           self.TRACE_FUNC_Y < y < self.TRACE_FUNC_Y + self.legend_height:
            return True
        else:
            return False

    def _to_logical_pos(self, pos):
        x_offset = self.view.horizontalScrollBar().value()
        y_offset = self.view.verticalScrollBar().value()
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)

    def _get_position(self, y):
        y_relative = y - self.legend_height

        return int(y_relative // self.trace_func_unit_height)

    def _get_bbl_from_y(self, y):
        position = self._get_position(y)
        return self.trace.get_bbl_from_position(position)

    def _get_func_from_func_name(self, func_name):
        return self.workspace.instance.kb.functions.function(name=func_name)

    def _get_func_from_y(self, y):
        position = self._get_position(y)
        func_name = self.trace.get_func_name_from_position(position)
        return self._get_func_from_func_name(func_name)
