import logging

from PySide2.QtGui import QPainter, QColor, QPen, QBrush
from PySide2.QtWidgets import QGraphicsView
from PySide2.QtCore import QPoint, Qt, QPointF, QRectF

from ...config import Conf
from ...utils.graph_layouter import GraphLayouter
from .qgraph import QBaseGraph

l = logging.getLogger('ui.widgets.qpg_graph')


class QSymExecGraph(QBaseGraph):

    LEFT_PADDING = 2000
    TOP_PADDING = 2000

    def __init__(self, current_state, workspace, symexec_view, parent=None):
        super(QSymExecGraph, self).__init__(workspace, parent=parent)

        self.state = current_state
        self._symexec_view = symexec_view

        self._graph = None
        self._edges = []

        self.key_pressed.connect(self._on_keypressed_event)
        self.state.am_subscribe(self._watch_state)

    def _init_widgets(self):
        super(QSymExecGraph, self)._init_widgets()

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

        node_sizes = {}
        for node in self.graph.nodes():
            self.blocks.add(node)
            node_sizes[node] = (node.width, node.height)
        gl = GraphLayouter(self.graph, node_sizes, node_compare_key=lambda n: 0)

        self._edges = gl.edges

        min_x, max_x, min_y, max_y = 0, 0, 0, 0

        for node, coords in gl.node_coordinates.items():
            node.x, node.y = coords

            min_x = min(min_x, node.x)
            max_x = max(max_x, node.x + node.width)
            min_y = min(min_y, node.y)
            max_y = max(max_y, node.y + node.height)

        min_x -= self.LEFT_PADDING
        max_x += self.LEFT_PADDING
        min_y -= self.TOP_PADDING
        max_y += self.TOP_PADDING
        width = (max_x - min_x) + 2 * self.LEFT_PADDING
        height = (max_y - min_y) + 2 * self.TOP_PADDING

        self._update_size()

        # scrollbars
        self.horizontalScrollBar().setRange(min_x, max_x)
        self.verticalScrollBar().setRange(min_y, max_y)

        self.setSceneRect(QRectF(min_x, min_y, width, height))

        self.viewport().update()

        self._update_size()

        if self.state.am_none():
            self.show_any()
        else:
            self.show_selected()

    def show_any(self):
        if self._proxies:
            proxy = next(iter(self._proxies.values()))
            self.ensureVisible(proxy)

    def show_selected(self):
        if not self.state.am_none():
            print("show_selected(): TODO")

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
                if block.selected:
                    self.state.am_obj = block.get_state()
                else:
                    self.state.am_obj = None
                self.state.am_event(src='qsymexec_graph')

                event.accept()
                return

        super(QSymExecGraph, self).mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        btn = event.button()
        if btn == Qt.LeftButton:
            pos = event.pos()
            block = self._get_block_by_pos(pos)
            if block is not None:
                block.on_mouse_doubleclicked(btn, self._to_graph_pos(pos))
                event.accept()
                return

        super(QSymExecGraph, self).mouseDoubleClickEvent(event)

    def _on_keypressed_event(self, key_event):
        """

        :param QKeyEvent event:
        :return:
        """

        key = key_event.key()

        if key == Qt.Key_Tab:
            self._symexec_view.switch_to_disassembly_view()
            return True

        return False

    def paintEvent(self, event):
        """
        Paint the graph.

        :param event:
        :return:
        """

        painter = QPainter(self.viewport())

        current_x = self.horizontalScrollBar().value()
        current_y = self.verticalScrollBar().value()

        painter.translate(self.width() // 2 - current_x, self.height() // 2 - current_y)

        painter.setFont(Conf.symexec_font)

        topleft_point = self._to_graph_pos(QPoint(0, 0))
        bottomright_point = self._to_graph_pos(QPoint(self.width(), self.height()))

        self._draw_edges(painter, topleft_point, bottomright_point)
        self._draw_nodes(painter, topleft_point, bottomright_point)

    def _watch_state(self, **kwargs):
        # for now we need to run this always to deselect the old block
        # if kwargs.get('src') == 'qsymexec_graph':
        #     return

        for block in self.blocks:
            if block.get_state() == self.state:
                block.selected = True
            else:
                block.selected = False

        self.viewport().update()

    #
    # Private methods
    #

    def _block_from_state(self, state):
        for block in self.blocks:
            if block.get_state() == state:
                return block
        return None

    def _draw_edges(self, painter, topleft_point, bottomright_point):
        for edge in self._edges:
            edge_coords = edge.coordinates

            color = QColor(0x70, 0x70, 0x70)
            pen = QPen(color)
            pen.setWidth(1.5)
            painter.setPen(pen)

            for from_, to_ in zip(edge_coords, edge_coords[1:]):
                start_point = QPointF(*from_)
                end_point = QPointF(*to_)
                # optimization: don't draw edges that are outside of the current scope
                if (start_point.x() > bottomright_point.x() or start_point.y() > bottomright_point.y()) and \
                        (end_point.x() > bottomright_point.x() or end_point.y() > bottomright_point.y()):
                    continue
                elif (start_point.x() < topleft_point.x() or start_point.y() < topleft_point.y()) and \
                        (end_point.x() < topleft_point.x() or end_point.y() < topleft_point.y()):
                    continue
                painter.drawPolyline((start_point, end_point))

            # arrow
            # end_point = self.mapToScene(*edges[-1])
            end_point = (edge_coords[-1][0], edge_coords[-1][1])
            arrow = [QPointF(end_point[0] - 3, end_point[1]), QPointF(end_point[0] + 3, end_point[1]),
                     QPointF(end_point[0], end_point[1] + 6)]
            brush = QBrush(color)
            painter.setBrush(brush)
            painter.drawPolygon(arrow)

    def _draw_nodes(self, painter, topleft_point, bottomright_point):
        if self.graph is None:
            return
        for node in self.graph.nodes():
            node.paint(painter)
