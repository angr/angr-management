
from PySide.QtGui import QGraphicsScene, QGraphicsView, QPainter, QKeyEvent, QApplication
from PySide.QtCore import Qt, QSize, Signal, QPoint


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

    def keyPressEvent(self, event):
        """
        KeyPress event

        :param PySide.QtGui.QKeyEvent event: The event
        :return: True/False
        """

        self.key_pressed.emit(event)

    def keyReleaseEvent(self, event):
        """
        KeyRelease event

        :param PySide.QtGui.QKeyEvent event: The event
        :return: True/False
        """

        self.key_released.emit(event)


class QBaseGraph(QZoomingGraphicsView):

    def __init__(self, workspace, parent=None):
        super(QBaseGraph, self).__init__(parent)

        self.workspace = workspace
        self.scene = None
        self._proxies = { }
        self._edge_paths = [ ]
        self.blocks = set()

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

    #
    # Event handlers
    #

    def mousePressEvent(self, event):

        if event.button() == Qt.LeftButton:
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
        x_offset = self.width() / 2 - self.horizontalScrollBar().value()
        y_offset = self.height() / 2 - self.verticalScrollBar().value()
        return QPoint(pos.x() - x_offset, pos.y() - y_offset)

    def _from_graph_pos(self, pos):
        x_offset = self.width() / 2 - self.horizontalScrollBar().value()
        y_offset = self.height() / 2 - self.verticalScrollBar().value()
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)

    def _get_block_by_pos(self, pos):
        pos = self._to_graph_pos(pos)
        x, y = pos.x(), pos.y()
        for b in self.blocks:
            if b.x <= x < b.x + b.width and b.y <= y < b.y + b.height:
                return b

        return None

