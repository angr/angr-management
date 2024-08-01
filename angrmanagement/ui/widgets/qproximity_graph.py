from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QPointF, Qt

from angrmanagement.utils.graph_layouter import GraphLayouter

from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QProximityGraphArrow

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.ui.views.proximity_view import ProximityView
    from angrmanagement.ui.widgets.qproximitygraph_block import QProximityGraphBlock
    from angrmanagement.utils.edge import Edge


_l = logging.getLogger(name=__name__)


class QProximityGraph(QZoomableDraggableGraphicsView):
    LEFT_PADDING = 2000
    TOP_PADDING = 2000

    def __init__(self, instance: Instance, proximity_view: ProximityView, parent=None) -> None:
        super().__init__(parent=parent)

        self._instance = instance
        self._proximity_view = proximity_view

        self._graph = None
        self.blocks = set()
        self._edges: list[Edge] = []
        self._arrows_by_src: dict[Any, list[QProximityGraphArrow]] = defaultdict(list)
        self._arrows_by_dst: dict[Any, list[QProximityGraphArrow]] = defaultdict(list)
        self._arrows: list[QProximityGraphArrow] = []

    @property
    def graph(self):
        return self._graph

    @graph.setter
    def graph(self, v) -> None:
        if v is not self._graph:
            self._graph = v
            self.reload()

    def reload(self) -> None:
        self.request_relayout()

    def refresh(self) -> None:
        for block in self.blocks:
            block.refresh()
        scene = self.scene()
        if scene is not None:
            scene.update(self.sceneRect())

    def request_relayout(self) -> None:
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
        # gl = TreeGraphLayouter(self.graph, node_sizes, vertical=True, horizontal_spacing=5, vertical_spacing=30,
        #                        layer_sorter=self._sort_nodes,
        #                        )
        gl = GraphLayouter(
            self.graph, node_sizes, node_sorter=self._sort_nodes, x_margin=2, y_margin=2, row_margin=2, col_margin=2
        )

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
            arrow = QProximityGraphArrow(self._proximity_view, edge, arrow_location="end", arrow_direction="down")
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

    def _sort_nodes(self, nodes: list[QProximityGraphBlock]) -> list[QProximityGraphBlock]:
        # Sort nodes based on the address of their first ref_at address in each function
        sorted_nodes = sorted(nodes, key=lambda x: next(iter(x._node.ref_at)) if x._node.ref_at else 0)
        return sorted_nodes

    #
    # Event handlers
    #

    def keyPressEvent(self, event) -> None:
        """

        :param QKeyEvent event:
        :return:
        """

        key = event.key()

        if key == Qt.Key.Key_Tab:
            self._symexec_view.switch_to_disassembly_view()
            event.accept()

        super().keyPressEvent(event)

    def on_block_hovered(self, block) -> None:
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
