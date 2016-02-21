import itertools
import functools
import time

import pygraphviz

from atom.api import List, Typed, Dict, ForwardTyped, observe
from enaml.widgets.api import Container
from enaml.widgets.frame import Frame, ProxyFrame
from enaml.core.declarative import d_
from enaml.qt.QtGui import QGraphicsScene, QGraphicsView, QPainterPath, QPainter
from enaml.qt.QtCore import QPointF, QRectF, Qt, QSize
from enaml.qt.qt_frame import QtFrame
from enaml.qt.qt_factories import QT_FACTORIES
from enaml.qt.qt_container import QtContainer

def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    args = [iter(iterable)] * n
    return itertools.izip_longest(*args, fillvalue=fillvalue)


class ZoomingGraphicsView(QGraphicsView):
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
            super(ZoomingGraphicsView, self).wheelEvent(event)

class ProxyGraph(ProxyFrame):
    declaration = ForwardTyped(lambda: Graph)


class QtGraph(QtFrame, ProxyGraph):
    widget = Typed(QGraphicsView)
    scene = Typed(QGraphicsScene)
    _proxies = Dict()
    _edge_paths = List()

    LEFT_PADDING = 1200
    TOP_PADDING = 1200

    def create_widget(self):
        self.scene = QGraphicsScene(self.parent_widget())
        self.widget = ZoomingGraphicsView(self.parent_widget())
        self.widget.setScene(self.scene)
        self.widget.setDragMode(QGraphicsView.ScrollHandDrag)
        self.widget.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)

    def child_added(self, child):
        super(QtGraph, self).child_added(child)
        self._proxy(child)

    def child_removed(self, child):
        super(QtGraph, self).child_removed(child)
        if child in self._proxies:
            self.scene.removeItem(self._proxies[child])

    def init_layout(self):
        super(QtGraph, self).init_layout()
        self.request_relayout()

    def _proxy(self, child):
        if child not in self._proxies:
            cw = child.widget
            if cw is not None:
                cw.setParent(None)
                self._proxies[child] = self.scene.addWidget(cw)

        return self._proxies[child]

    def request_relayout(self):
        # y = 0.0

        # for child in self.children():
        #     if not isinstance(child, QtContainer):
        #         continue
        #     scene_proxy = self._proxies[child]
        #     width, height = child._layout_manager.best_size()
        #     scene_proxy.setPos(0.0, y)
        #     y += height + 25.0

        for p in self._edge_paths:
            self.scene.removeItem(p)
        self._edge_paths = []

        g = pygraphviz.AGraph(directed=True)
        g.graph_attr['nodesep'] = 100
        g.graph_attr['ranksep'] = 50
        g.node_attr['shape'] = 'rect'

        children_names = {child.declaration.name for child in self.children() if isinstance(child, QtContainer)}

        if any(from_ not in children_names or to not in children_names for (from_, to) in self.declaration.edges):
            # hasn't finished being set up yet
            return

        for child in self.children():
            if not isinstance(child, QtContainer):
                continue
            scene_proxy = self._proxy(child)
            width, height = child._layout_manager.best_size()
            scene_proxy.setGeometry(QRectF(0.0, 0.0, width, height))
            g.add_node(child.declaration.name, width=width, height=height)

        for from_, to in self.declaration.edges:
            g.add_edge(from_, to)

        before = time.time()
        g.layout(prog='dot')
        after = time.time()

        for child in self.children():
            if not isinstance(child, QtContainer):
                continue
            scene_proxy = self._proxies[child]
            node = g.get_node(child.declaration.name)
            center_x, center_y = (-float(v)/72.0 for v in node.attr['pos'].split(','))
            width, height = child._layout_manager.best_size()
            x = center_x - (width / 2.0)
            y = center_y - (height / 2.0)
            scene_proxy.setPos(x, y)

        for from_, to in self.declaration.edges:
            if from_ not in children_names or to not in children_names:
                continue
            edge = g.get_edge(from_, to)
            # TODO: look at below code
            all_points = [tuple(-float(v)/72.0 for v in t.strip('e,').split(',')) for t in edge.attr['pos'].split(' ')]
            arrow = all_points[0]
            start_point = all_points[1]

            painter = QPainterPath(QPointF(*start_point))
            for c1, c2, end in grouper(all_points[2:], 3):
                painter.cubicTo(QPointF(*c1), QPointF(*c2), QPointF(*end))

            self._edge_paths.append(self.scene.addPath(painter))

        rect = self.scene.itemsBoundingRect()
        # Enlarge the rect so there is enough room at right and bottom
        rect.setX(rect.x() - self.LEFT_PADDING)
        rect.setY(rect.y() - self.TOP_PADDING)
        rect.setWidth(rect.width() + 2 * self.LEFT_PADDING)
        rect.setHeight(rect.height() + 2 * self.TOP_PADDING)

        self.scene.setSceneRect(rect)
        self.widget.viewport().update()

        self.show_selected()

    def minimumSizeHint(self):
        return QSize(0, 0)

    def show_selected(self):
        # TODO: make more efficient?
        for child, proxy in self._proxies.items():
            if isinstance(child, QtContainer) and child.declaration is not None and child.declaration.name == self.declaration.selected:
                self.widget.ensureVisible(proxy)
                break

QT_FACTORIES['Graph'] = lambda: QtGraph


class Graph(Frame):
    #: The edges (as names) of the Graph
    edges = d_(List())

    #: The "selected" node that should be visible
    selected = d_(Typed(str))

    proxy = Typed(ProxyGraph)

    hug_width = 'weak'
    hug_height = 'weak'

    def child_added(self, child):
        super(Graph, self).child_added(child)
        # print "got a child! %s" % child
        # if hasattr(child, 'path'):
        #     print "has id: %s" % child.path.path_id
        if isinstance(child, Container):
            self.request_relayout()

    @observe('edges')
    def _update(self, change):
        self.request_relayout()

    @observe('selected')
    def _selected_update(self, change):
        if self.proxy is not None:
            self.proxy.show_selected()

