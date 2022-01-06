import logging
from collections import defaultdict
from typing import Optional, Any, List, Dict, TYPE_CHECKING, Set

from PySide2 import QtWidgets, QtCore

from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QDataDepGraphArrow
from ...utils.edge import Edge
from ...utils.graph_layouter import GraphLayouter

if TYPE_CHECKING:
    from networkx import DiGraph

    from angrmanagement.ui.workspace import Workspace
    from angrmanagement.ui.views.data_dep_view import DataDepView
    from angrmanagement.ui.widgets.qdatadepgraph_block import QDataDepGraphBlock

_l = logging.getLogger(__name__)


class QDataDepPreviewGraph(QZoomableDraggableGraphicsView):
    def __init__(self, parent: QtWidgets.QWidget):
        super().__init__(parent)

        self._display_node: Optional['QDataDepGraphBlock'] = None

    @property
    def node(self) -> Optional['QDataDepGraphBlock']:
        return self._display_node

    @node.setter
    def node(self, n: Optional['QDataDepGraphBlock']):
        self._display_node = n
        if not self._display_node:
            return

        self.centerOn(self._display_node)
        self.zoom()
        self.refresh()

    def reload(self):
        pass

    def refresh(self):
        self._display_node.refresh()
        if scene := self.scene():
            scene.update(self.sceneRect())

    def _initial_position(self):
        if scene := self.scene():
            return scene.itemsBoundingRect().center()
        return QtCore.QPointF(0, 0)


class QDataDepPreview(QtWidgets.QFrame):
    def __init__(self, parent: QtWidgets.QWidget):
        super().__init__(parent)
        self.setFrameStyle(QtWidgets.QFrame.Panel | QtWidgets.QFrame.Raised)
        self.setStyleSheet(self.styleSheet() + "color: black;")
        self._preview_graph = QDataDepPreviewGraph(self)
        self._layout_manager = QtWidgets.QVBoxLayout(self)
        self._init_widgets()

    @property
    def preview_graph(self) -> QDataDepPreviewGraph:
        return self._preview_graph

    def _init_widgets(self):
        self._layout_manager.addWidget(self.preview_graph)


class QDataDepGraph(QZoomableDraggableGraphicsView):
    LEFT_PADDING = 4000
    TOP_PADDING = 4000

    def __init__(self, workspace: 'Workspace', data_dep_view: 'DataDepView', parent: QtWidgets.QWidget):
        super().__init__(parent)

        self._workspace = workspace
        self._data_dep_view = data_dep_view

        self._node_preview = QDataDepPreview(parent)
        self._node_preview.preview_graph._reset_scene()
        self._node_preview.hide()

        self._graph: Optional['DiGraph'] = None
        self.nodes = set()
        self._edges: List[Edge] = []
        self._arrows_by_src: Dict[Any, List[QDataDepGraphArrow]] = defaultdict(list)
        self._arrows_by_dst: Dict[Any, List[QDataDepGraphArrow]] = defaultdict(list)
        self._arrows: List[QDataDepGraphArrow] = []

    @property
    def graph(self) -> Optional['DiGraph']:
        return self._graph

    @graph.setter
    def graph(self, new_graph: 'DiGraph'):
        if new_graph is not self._graph:
            self._graph = new_graph
            self.reload()

    def reload(self):
        self.request_relayout()

    def refresh(self):
        for node in self.nodes:
            node.refresh()
        if scene := self.scene():
            scene.update(self.sceneRect())

    def request_relayout(self):
        self._reset_scene()
        if self.graph is None:
            return

        # Remove all arrows
        self._arrows.clear()
        self._arrows_by_src.clear()
        self._arrows_by_dst.clear()

        # Remove all nodes
        self.nodes.clear()

        node_sizes = {}
        for node in self.graph.nodes():
            self.nodes.add(node)
            node_sizes[node] = node.width, node.height
        gl = GraphLayouter(self.graph, node_sizes, node_sorter=lambda nodes: nodes,
                           x_margin=2, y_margin=2, row_margin=10, col_margin=2)

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

        # Draw edges
        for edge in self._edges:
            arrow = QDataDepGraphArrow(self._data_dep_view, edge, arrow_location="end", arrow_direction="down")
            self._arrows.append(arrow)
            self._arrows_by_src[edge.src].append(arrow)
            self._arrows_by_dst[edge.dst].append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QtCore.QPointF(*edge.coordinates[0]))

        min_x -= self.LEFT_PADDING
        max_x += self.LEFT_PADDING
        min_y -= self.TOP_PADDING
        max_y += self.TOP_PADDING

        self._reset_view()

    def _initial_position(self):
        if scene := self.scene():
            return scene.itemsBoundingRect().center()
        return QtCore.QPointF(0, 0)

    def _is_on_screen(self, item: QtWidgets.QGraphicsItem) -> bool:
        screen_rect = self.mapToScene(self.viewport().geometry()).boundingRect()
        tl = screen_rect.topLeft()
        br = screen_rect.bottomRight()
        return tl.x() <= item.x() <= br.x() and tl.y() <= item.y() <= br.y()

    def handle_preview_request(self, arrow: QDataDepGraphArrow):
        self._node_preview.preview_graph.setScene(self.scene())
        dst_node: QtWidgets.QGraphicsItem = arrow.edge.dst
        src_node: QtWidgets.QGraphicsItem = arrow.edge.src

        if not self._is_on_screen(dst_node):
            self._node_preview.preview_graph.node = dst_node
        elif not self._is_on_screen(src_node):
            self._node_preview.preview_graph.node = src_node
        else:
            self._node_preview.preview_graph.node = None

        if not self._node_preview.preview_graph.node:
            # Both widgets are visible, no need to show the preview
            return

        # Size to fit in top right
        prv_w = self._node_preview.preview_graph.node.width
        prv_h = self._node_preview.preview_graph.node.height

        self._node_preview.setGeometry(
            self.rect().topRight().x() - prv_w,
            0,
            prv_w,
            prv_h
        )
        self._node_preview.show()

    def hide_preview(self):
        self._node_preview.hide()

    def get_ancestors(self, node: 'QDataDepGraphBlock',
                      parent_nodes: Optional[Set['QDataDepGraphBlock']] = None) -> Set['QDataDepGraphBlock']:
        if parent_nodes is None:
            parent_nodes = set()
        parent_nodes.add(node)

        for dep_arrow in self._arrows_by_dst[node]:
            self.get_ancestors(dep_arrow.edge.src, parent_nodes)

        return parent_nodes

    def get_descendants(self, node: 'QDataDepGraphBlock',
                        child_nodes: Optional[Set['QDataDepGraphBlock']] = None) -> Set['QDataDepGraphBlock']:
        if child_nodes is None:
            child_nodes = set()
        child_nodes.add(node)

        for dep_arrow in self._arrows_by_src[node]:
            self.get_descendants(dep_arrow.edge.dst, child_nodes)

        return child_nodes

    # def on_block_hovered(self, block: Optional['QDataDepGraphBlock']):
    #     if block is None:
    #         return
