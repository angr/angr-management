
import pygraphviz

from PySide.QtGui import QPainterPath
from PySide.QtCore import QPointF, QRectF

from ...utils.graph import grouper
from .qgraph import QBaseGraph

class QPathGroupGraph(QBaseGraph):

    LEFT_PADDING = 200
    TOP_PADDING = 200

    def __init__(self, parent=None):

        super(QPathGroupGraph, self).__init__(parent)

        self._graph = None
        self._selected = None

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, v):
        self._selected = v
        self.show_selected()

    @property
    def graph(self):
        return self._graph

    @graph.setter
    def graph(self, v):
        if v is not self._graph:
            self._graph = v
            self.reload()

    def reload(self):
        self.request_relayout()

    def request_relayout(self):

        if self.graph is None:
            return

        # remove all edges
        for p in self._edge_paths:
            self.scene.removeItem(p)

        # remove all nodes
        self.remove_all_children()
        self._edge_paths = []

        g = pygraphviz.AGraph(directed=True)
        g.graph_attr['nodesep'] = 100
        g.graph_attr['ranksep'] = 50
        g.node_attr['shape'] = 'rect'

        for node in self.graph.nodes_iter():
            scene_proxy = self._proxy(node)
            size = node.size()
            width, height = size.width(), size.height()
            scene_proxy.setGeometry(QRectF(0.0, 0.0, width, height))
            g.add_node(node, width=width, height=height)

        for from_, to in self.graph.edges_iter():
            g.add_edge(from_, to)

        g.layout(prog='dot')

        for node in self.graph.nodes_iter():
            scene_proxy = self._proxies[node]
            n = g.get_node(node)
            center_x, center_y = (-float(v) / 72.0 for v in n.attr['pos'].split(','))
            size = node.size()
            width, height = size.width(), size.height()
            x = center_x - (width / 2.0)
            y = center_y - (height / 2.0)
            scene_proxy.setPos(x, y)

        for from_, to in self.graph.edges_iter():
            edge = g.get_edge(from_, to)
            # TODO: look at below code
            all_points = [tuple(-float(v) / 72.0 for v in t.strip('e,').split(',')) for t in
                          edge.attr['pos'].split(' ')]
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
        self.viewport().update()

        if self.selected is not None:
            self.show_selected()
        else:
            self.show_any()

    def show_any(self):
        if self._proxies:
            proxy = next(self._proxies.itervalues())
            self.ensureVisible(proxy)

    def show_selected(self):
        if self.selected is not None:
            proxy = self._proxies.get(self.selected, None)
            if proxy is not None:
                self.ensureVisible(proxy)
