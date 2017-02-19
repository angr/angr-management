
import pygraphviz

from PySide.QtGui import QGraphicsScene, QGraphicsView, QPainterPath, QPainter, QKeyEvent
from PySide.QtCore import QPointF, QRectF, Qt, QSize, Signal

from ...utils.graph import grouper


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

    def __init__(self, parent=None):
        super(QBaseGraph, self).__init__(parent)

        self.scene = None
        self._proxies = { }
        self._edge_paths = [ ]

        self._init_widgets()

    def _init_widgets(self):
        self.scene = QGraphicsScene(self.parent())
        self.setScene(self.scene)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform |
                            QPainter.HighQualityAntialiasing
                            )

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
