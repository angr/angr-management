import logging

from PySide2.QtWidgets import QGraphicsScene, QGraphicsView
from PySide2.QtGui import QPainter, QKeyEvent
from PySide2.QtCore import Qt, QSize, Signal, QPoint, QEvent

from ...data.instance import ObjectContainer

_l = logging.getLogger('ui.widgets.qgraph')


class QZoomingGraphicsView(QGraphicsView):
    key_pressed = Signal(QKeyEvent)
    key_released = Signal(QKeyEvent)

    def __init__(self, parent):
        super(QZoomingGraphicsView, self).__init__(parent)

    def sizeHint(self):
        return QSize(300, 300)

    def wheelEvent(self, event):
        if event.modifiers() & Qt.ControlModifier == Qt.ControlModifier:
            zoomInFactor = 1.25
            zoomOutFactor = 1 / zoomInFactor

            # Save the scene pos
            oldPos = self.mapToScene(event.pos())

            # Zoom
            if event.delta() > 0:
                zoomFactor = zoomInFactor
            else:
                zoomFactor = zoomOutFactor
            self.scale(zoomFactor, zoomFactor)

            # Get the new position
            newPos = self.mapToScene(event.pos())

            # Move scene to old position
            delta = newPos - oldPos
            self.translate(delta.x(), delta.y())
        else:
            super(QZoomingGraphicsView, self).wheelEvent(event)

    def event(self, event):
        """
        Reimplemented to capture the Tab keypress event.
        """

        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.key_pressed.emit(event)
            return True

        return super(QZoomingGraphicsView, self).event(event)

    def keyPressEvent(self, event):
        """
        KeyPress event

        :param PySide2.QtGui.QKeyEvent event: The event
        :return: True/False
        """

        self.key_pressed.emit(event)

    def keyReleaseEvent(self, event):
        """
        KeyRelease event

        :param PySide2.QtGui.QKeyEvent event: The event
        :return: True/False
        """

        self.key_released.emit(event)


class QBaseGraph(QZoomingGraphicsView):

    def __init__(self, workspace, parent=None, allow_dragging=True):
        super(QBaseGraph, self).__init__(parent)

        self.workspace = workspace
        self.scene = None
        self._proxies = {}
        self._edge_paths = []
        self.blocks = set()

        self.selected_insns = ObjectContainer(set(), 'The currently selected instructions')
        self.selected_operands = set()
        self._insn_addr_to_block = {}
        self._allow_dragging = allow_dragging

        # scrolling
        self._is_scrolling = False
        self._scrolling_start = None

        self._init_widgets()

    def add_child(self, child):
        self._proxy(child)

    def remove_child(self, child):
        if child in self._proxies:
            self.scene.removeItem(self._proxies[child])

    def _proxy(self, child):
        if child not in self._proxies:
            child.setParent(None)
            self._proxies[child] = self.scene.addWidget(child)
            return self._proxies[child]

        return self._proxies[child]

    def remove_all_children(self):
        for child in self._proxies:
            self.scene.removeItem(self._proxies[child])
            child.setParent(self)
        self._proxies.clear()

    def request_relayout(self):
        raise NotImplementedError()

    def update_label(self, label_addr, is_renaming=False):
        # if it's just a renaming, we simply update the text of the label
        if is_renaming:
            if label_addr in self._insn_addr_to_block:
                block = self._insn_addr_to_block[label_addr]
                block.update_label(label_addr)

            else:
                # umm not sure what's going wrong
                _l.error('Label address %#x is not found in the current function.', label_addr)

        else:
            self.reload()

    def update_comment(self, comment_addr, comment_text):
        if comment_addr in self._insn_addr_to_block:
            block = self._insn_addr_to_block[comment_addr]
            insn = block.addr_to_insns[comment_addr]
            if insn:
                insn.set_comment(comment_text)
        else:
            # umm not sure what's going wrong
            _l.error('Label address %#x is not found in the current function.', comment_addr)

        self.reload()

    def select_instruction(self, insn_addr, unique=True):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            # the instruction does not belong to the current function
            return

        if insn_addr not in self.selected_insns:
            if unique:
                # unselect existing ones
                self.unselect_all_instructions()
                self.selected_insns.add(insn_addr)
            else:
                self.selected_insns.add(insn_addr)

            block.addr_to_insns[insn_addr].select()

        # Notify subscribers BEFORE we update the viewport so they can make any further changes
        self.selected_insns.am_event(graph=self, addr=insn_addr, block=block)
        self.viewport().update()

    def unselect_instruction(self, insn_addr):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if insn_addr in self.selected_insns:
            self.selected_insns.remove(insn_addr)

            block.addr_to_insns[insn_addr].unselect()

        self.viewport().update()

    def unselect_all_instructions(self):
        for insn_addr in self.selected_insns.copy():
            self.unselect_instruction(insn_addr)

    def select_operand(self, insn_addr, operand_idx, unique=True):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            # the instruction does not belong to the current function
            return

        if (insn_addr, operand_idx) not in self.selected_operands:
            if unique:
                # unselect existing ones
                self.unselect_all_operands()
                self.selected_operands = { (insn_addr, operand_idx) }
            else:
                self.selected_operands.add((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].select_operand(operand_idx)

        self.viewport().update()

    def unselect_operand(self, insn_addr, operand_idx):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if (insn_addr, operand_idx) in self.selected_operands:
            self.selected_operands.remove((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].unselect_operand(operand_idx)

        self.viewport().update()

    def unselect_all_operands(self):
        for insn_addr, operand_idx in self.selected_operands.copy():
            self.unselect_operand(insn_addr, operand_idx)

    def show_selected(self):
        if self.selected_insns:
            addr = next(iter(self.selected_insns))
            self.show_instruction(addr)

    def show_instruction(self, insn_addr):
        raise NotImplemented()

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        if self._allow_dragging and event.button() == Qt.LeftButton:
            # dragging the entire graph
            self.setDragMode(QGraphicsView.ScrollHandDrag)
            self._is_scrolling = True
            self._scrolling_start = (event.x(), event.y())
            self.viewport().grabMouse()
            event.accept()

    def mouseMoveEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if self._is_scrolling:
            pos = event.pos()
            delta = (pos.x() - self._scrolling_start[0], pos.y() - self._scrolling_start[1])
            self._scrolling_start = (pos.x(), pos.y())

            # move the graph
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - delta[0])
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - delta[1])
            event.accept()

    def mouseReleaseEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton and self._is_scrolling:
            self._is_scrolling = False
            self.setDragMode(QGraphicsView.NoDrag)
            self.viewport().releaseMouse()
            event.accept()

    #
    # Private methods
    #

    def _init_widgets(self):
        self.scene = QGraphicsScene(self.parent())
        self.setScene(self.scene)
        # self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform |
                            QPainter.HighQualityAntialiasing
                            )

        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.horizontalScrollBar().setSingleStep(16)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.verticalScrollBar().setSingleStep(16)

    def _set_pos(self, widget, coord):
        """
        Set the position of a widget in the scene with QTransform.
        Solves this problem:
        http://stackoverflow.com/questions/23342039/qgraphicsproxywidgetsetposqreal-x-qreal-y-doesnt-place-correctly-in-a-qgra

        :param widget: The widget to set position.
        :param coord: The new coordinate.
        :return: None
        """
        widget.resetTransform()
        trans = widget.transform()
        widget.setTransform(trans.translate(coord.x(), coord.y()))

    def _update_size(self):

        # update scrollbars
        self.horizontalScrollBar().setPageStep(self.width())
        self.verticalScrollBar().setPageStep(self.height())

    def _to_graph_pos(self, pos):
        x_offset = self.width() // 2 - self.horizontalScrollBar().value()
        y_offset = self.height() // 2 - self.verticalScrollBar().value()
        return QPoint(pos.x() - x_offset, pos.y() - y_offset)

    def _from_graph_pos(self, pos):
        x_offset = self.width() // 2 - self.horizontalScrollBar().value()
        y_offset = self.height() // 2 - self.verticalScrollBar().value()
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)

    def _get_block_by_pos(self, pos):
        pos = self._to_graph_pos(pos)
        x, y = pos.x(), pos.y()
        for b in self.blocks:
            if b.x <= x < b.x + b.width and b.y <= y < b.y + b.height:
                return b

        return None

    def _clear_insn_addr_block_mapping(self):
        self._insn_addr_to_block.clear()

    def _add_insn_addr_block_mapping(self, insn_addr, block):
        self._insn_addr_to_block[insn_addr] = block
