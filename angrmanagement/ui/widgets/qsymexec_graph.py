
import logging

from PySide.QtGui import QPainter, QGraphicsView
from PySide.QtCore import QPoint, Qt

from ...utils.graph_layouter import GraphLayouter
from .qgraph import QBaseGraph

l = logging.getLogger('ui.widgets.qpg_graph')


class QSymExecGraph(QBaseGraph):

    LEFT_PADDING = 200
    TOP_PADDING = 200

    def __init__(self, workspace, parent=None):

        super(QSymExecGraph, self).__init__(workspace, parent=parent)

        self._graph = None
        self._selected = None

    def _init_widgets(self):
        super(QSymExecGraph, self)._init_widgets()

        self.setDragMode(QGraphicsView.ScrollHandDrag)

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
        self.blocks.clear()
        self.remove_all_children()
        self._edge_paths = []

        node_sizes = { }
        for node in self.graph.nodes():
            self.blocks.add(node)
            node_sizes[node] = (100, 100)
        gl = GraphLayouter(self.graph, node_sizes,
                           compare_nodes_func=lambda n0, n1: 0)

        for node, coords in gl.node_coordinates.iteritems():
            node.x, node.y = coords

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
            print "show_selected(): TODO"

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        btn = event.button()
        if btn == Qt.LeftButton:
            pos = event.pos()
            block = self._get_block_by_pos(pos)
            if block is not None:
                block.on_mouse_pressed(btn, self._to_graph_pos(pos))
            event.accept()

    def paintEvent(self, event):
        """
        Paint the graph.

        :param event:
        :return:
        """

        painter = QPainter(self.viewport())

        current_x = self.horizontalScrollBar().value()
        current_y = self.verticalScrollBar().value()

        painter.translate(self.width() / 2 - current_x, self.height() / 2 - current_y)

        painter.setFont(self.workspace.symexec_font)

        topleft_point = self._to_graph_pos(QPoint(0, 0))
        bottomright_point = self._to_graph_pos(QPoint(self.width(), self.height()))

        self._draw_edges(painter, topleft_point, bottomright_point)
        self._draw_nodes(painter, topleft_point, bottomright_point)

    #
    # Private methods
    #

    def _draw_edges(self, painter, topleft_point, bottomright_point):
        pass

    def _draw_nodes(self, painter, topleft_point, bottomright_point):
        if self.graph is None:
            return
        for node in self.graph.nodes():
            node.paint(painter)
