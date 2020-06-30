from collections import defaultdict
from typing import TYPE_CHECKING, List, Dict, Any
import logging

from PySide2.QtCore import Qt, QPointF

from ...utils.edge import Edge
from ...utils.tree_graph_layouter import TreeGraphLayouter
from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QDepGraphArrow

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
        self._edges: List[Edge] = [ ]
        self._arrows_by_src: Dict[Any,List[QDepGraphArrow]] = defaultdict(list)
        self._arrows_by_dst: Dict[Any,List[QDepGraphArrow]] = defaultdict(list)
        self._arrows: List[QDepGraphArrow] = [ ]

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

    def refresh(self):
        for block in self.blocks:
            block.refresh()
        self.scene().update(self.sceneRect())

    def request_relayout(self):
        self._reset_scene()
        if self.graph is None:
            return

        # remove all arrows
        self._arrows.clear()
        self._arrows_by_src.clear()
        self._arrows_by_dst.clear()

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
            arrow = QDepGraphArrow(self._dep_view, edge, arrow_location="start", arrow_direction="left")
            self._arrows.append(arrow)
            self._arrows_by_src[edge.src].append(arrow)
            self._arrows_by_dst[edge.dst].append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))

        min_x -= self.LEFT_PADDING
        max_x += self.LEFT_PADDING
        min_y -= self.TOP_PADDING
        max_y += self.TOP_PADDING

        self._reset_view()

    def _initial_position(self):
        ibr = self.scene().itemsBoundingRect()
        return ibr.center()

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

    def on_block_hovered(self, block):
        if block is None:
            return
        scene = self.scene()
        # move all relevant arrows to the top
        if block in self._arrows_by_src:
            arrows = set(self._arrows_by_src[block])
            for arrow in arrows:
                for item in scene.collidingItems(arrow):
                    if item in arrows:
                        continue
                    item.stackBefore(arrow)

        if block in self._arrows_by_dst:
            arrows = set(self._arrows_by_dst[block])
            for arrow in arrows:
                for item in scene.collidingItems(arrow):
                    if item in arrows:
                        continue
                    item.stackBefore(arrow)
