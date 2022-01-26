import logging
from collections import defaultdict
from typing import Optional, Any, List, Dict, TYPE_CHECKING, Set

from PySide2 import QtWidgets, QtCore, QtGui

from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QDataDepGraphArrow, QDataDepGraphAncestorLine
from ...utils.edge import Edge
from ...utils.graph_layouter import GraphLayouter

if TYPE_CHECKING:
    from networkx import DiGraph

    from angrmanagement.ui.workspace import Workspace
    from angrmanagement.ui.views.data_dep_view import DataDepView
    from angrmanagement.ui.widgets.qdatadepgraph_block import QDataDepGraphBlock

_l = logging.getLogger(__name__)


class QDataDepPreviewGraph(QZoomableDraggableGraphicsView):
    """
    Displays a zoomed-in preview of an off-screen node on a QDataDepArrow hover
    """

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
        # self.zoom(restore=True)
        self.refresh()
        self.setFixedSize(self.sizeHint())

    def sizeHint(self) -> QtCore.QSize:
        if not self._display_node:
            return QtCore.QSize(0, 0)
        return QtCore.QSize(self._display_node.width, self._display_node.height)

    def reload(self):
        pass

    def refresh(self):
        self._display_node.refresh()
        scene = self.scene()
        if scene:
            scene.update(self.sceneRect())

    def _initial_position(self):
        scene = self.scene()
        if scene:
            return scene.itemsBoundingRect().center()
        return QtCore.QPointF(0, 0)


class QDataDepPreview(QtWidgets.QFrame):
    """Frame for holding a preview scene"""
    _SRC_JUMP_TEXT = "Jump to source node?"
    _DST_JUMP_TEXT = "Jump to destination node?"

    def __init__(self, parent: QtWidgets.QWidget):
        super().__init__(parent)
        self.preview_graph = QDataDepPreviewGraph(self)
        self._caption = QtWidgets.QLabel(self)
        self.setStyleSheet(self.styleSheet() + "border: 2px solid black;")
        self._layout_manager = QtWidgets.QVBoxLayout(self)
        self._init_widgets()

    def set_caption(self, show_src_caption: bool):
        if show_src_caption:
            self._caption.setText(self._SRC_JUMP_TEXT)
        else:
            self._caption.setText(self._DST_JUMP_TEXT)

    def _init_widgets(self):
        parent_background_color = self.parent().palette().color(QtGui.QPalette.Background)
        self.setStyleSheet(f"background-color: {parent_background_color.name()};")
        self.setFrameStyle(QtWidgets.QFrame.Raised | QtWidgets.QFrame.Panel)
        self._layout_manager.addWidget(self.preview_graph, 0, QtCore.Qt.AlignCenter)
        self._layout_manager.addWidget(self._caption, 1, QtCore.Qt.AlignCenter)


class QDataDepGraph(QZoomableDraggableGraphicsView):
    """Graph that displays a collection of QDataDepGraphBlocks"""
    LEFT_PADDING = 4000
    TOP_PADDING = 4000

    def __init__(self, workspace: 'Workspace', data_dep_view: 'DataDepView', parent: QtWidgets.QWidget):
        super().__init__(parent)

        self._workspace = workspace
        self._data_dep_view = data_dep_view

        self._node_preview = QDataDepPreview(parent)
        self._node_preview.preview_graph._reset_scene()
        self._node_preview.hide()

        self._graph: Optional['DiGraph'] = None  # Graph to render
        self._reference_data_dep_graph: Optional['DiGraph'] = None  # Graph from analysis, used to check edge data
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

    @property
    def ref_graph(self) -> Optional['DiGraph']:
        return self._reference_data_dep_graph

    @ref_graph.setter
    def ref_graph(self, new_ref: 'DiGraph'):
        self._reference_data_dep_graph = new_ref

    def reload(self):
        self.request_relayout()

    def refresh(self):
        for node in self.nodes:
            node.refresh()
        scene = self.scene()
        if scene:
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
                           x_margin=5, y_margin=5, row_margin=20, col_margin=10)

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
            edge_data = self.ref_graph.get_edge_data(edge.src.node, edge.dst.node)
            edge_label = edge_data.get('label', None) if edge_data else None
            if edge_label and edge_label == 'ancestor':
                arrow = QDataDepGraphAncestorLine(self._data_dep_view,
                                                  edge,
                                                  arrow_location="end",
                                                  arrow_direction="down")
            else:
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
        scene = self.scene()
        if scene:
            return scene.itemsBoundingRect().center()
        return QtCore.QPointF(0, 0)

    def _is_on_screen(self, item: QtWidgets.QGraphicsItem) -> bool:
        screen_rect = self.mapToScene(self.viewport().geometry()).boundingRect()
        tl = screen_rect.topLeft()
        br = screen_rect.bottomRight()
        return tl.x() <= item.x() <= br.x() and tl.y() <= item.y() <= br.y()

    def handle_preview_request(self, arrow: QDataDepGraphArrow, jump_to_dst: bool):
        self._node_preview.preview_graph.setScene(self.scene())
        dst_node: QtWidgets.QGraphicsItem = arrow.edge.dst
        src_node: QtWidgets.QGraphicsItem = arrow.edge.src

        if jump_to_dst:
            self._node_preview.preview_graph.node = dst_node
            self._node_preview.set_caption(False)
        else:
            self._node_preview.preview_graph.node = src_node
            self._node_preview.set_caption(True)

        # Size to fit in top right
        dim = self._node_preview.sizeHint()
        prv_w = dim.width()
        prv_h = dim.height()

        self._node_preview.setGeometry(
            self.rect().topRight().x() - prv_w,
            0,
            prv_w,
            prv_h
        )
        self._node_preview.show()

    def hide_preview(self):
        self._node_preview.hide()

    def jump_to_neighbor(self, arrow: 'QDataDepGraphArrow', jump_to_dst: bool, event_pos: QtCore.QPoint):
        """
        Handler for double click on a QDataDepGraphArrow, recenters view on the source or destination block
        :param arrow: Calling arrow
        :param jump_to_dst: Whether the jump should be made to the arrow's source or destination node
        """
        jump_block = arrow.edge.dst if jump_to_dst else arrow.edge.src
        jump_block_origin_pos = jump_block.scenePos()

        # Get center position of the block
        jump_block_bottom_right_pos = QtCore.QPoint(
            jump_block_origin_pos.x() + jump_block.width,
            jump_block_origin_pos.y() + jump_block.height
        )
        jump_block_center_pos = QtCore.QPoint(
            (jump_block_origin_pos.x() + jump_block_bottom_right_pos.x()) // 2,
            (jump_block_origin_pos.y() + jump_block_bottom_right_pos.y()) // 2
        )
        delta = event_pos - jump_block_center_pos
        self.translate(delta.x(), delta.y())

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
