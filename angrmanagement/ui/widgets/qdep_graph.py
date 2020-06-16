from typing import TYPE_CHECKING, List
import logging

from PySide2.QtGui import QColor, QPen, QBrush
from PySide2.QtCore import Qt, QPointF

from ...utils.tree_graph_layouter import TreeGraphLayouter
from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QGraphArrowBezier

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace
    from angrmanagement.ui.views.dep_view import DependencyView


_l = logging.getLogger(name=__name__)


class QDependencyGraph(QZoomableDraggableGraphicsView):

    LEFT_PADDING = 2000
    TOP_PADDING = 2000

    def __init__(self, workspace: 'Workspace', dep_view: 'DependencyView', parent=None):
        super().__init__(parent=parent)

        self._workspace = workspace
        self._dep_view = dep_view

        self._graph = None
        self.blocks = set()
        self._edges = [ ]
        self._arrows: List[QGraphArrowBezier] = [ ]

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
        self._reset_scene()
        if self.graph is None:
            return

        # remove all arrows
        scene = self.scene()
        for p in self._arrows:
            scene.removeItem(p)

        # remove all nodes
        self.blocks.clear()

        node_sizes = {}
        for node in self.graph.nodes():
            self.blocks.add(node)
            node_sizes[node] = (node.width, node.height)
        gl = TreeGraphLayouter(self.graph, node_sizes)

        self._edges = gl.edges

        min_x, max_x, min_y, max_y = 0, 0, 0, 0

        scene = self.scene()
        for node, (x, y) in gl.node_coordinates.items():
            scene.addItem(node)
            node.setPos(x, y)
            min_x = min(min_x, node.x())
            max_x = max(max_x, node.x() + node.width)
            min_y = min(min_y, node.y())
            max_y = max(max_y, node.y() + node.height)

        # draw edges
        for edge in self._edges:
            arrow = QGraphArrowBezier(edge, arrow_direction="right")
            self._arrows.append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))

        min_x -= self.LEFT_PADDING
        max_x += self.LEFT_PADDING
        min_y -= self.TOP_PADDING
        max_y += self.TOP_PADDING

        self._reset_view()

    #
    # Event handlers
    #

    def keyPressEvent(self, event):
        """

        :param QKeyEvent event:
        :return:
        """

        key = event.key()

        if key == Qt.Key_Tab:
            self._symexec_view.switch_to_disassembly_view()
            event.accept()

        super().keyPressEvent(event)

    #
    # Private methods
    #

    def _initial_position(self):
        ibr = self.scene().itemsBoundingRect()
        return ibr.center()

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
