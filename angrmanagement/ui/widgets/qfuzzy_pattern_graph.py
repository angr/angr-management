from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.known_patterns import PAnyStmt
from angr.analyses.decompiler.known_patterns.edit import describe
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import QGraphicsSimpleTextItem

from angrmanagement.config import Conf
from angrmanagement.utils.graph_layouter import GraphLayouter

from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QGraphArrow
from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    import networkx
    from angr.analyses.decompiler.known_patterns import PatternNode
    from angr.analyses.decompiler.known_patterns.edit import NodePath

    from angrmanagement.ui.views.fuzzy_pattern_view import FuzzyPatternView
    from angrmanagement.utils.edge import Edge

_l = logging.getLogger(__name__)

# fill colors by how a node takes part in matching
_FILL = {
    "required": QColor(0xFA, 0xFA, 0xFA),
    "optional": QColor(0xE8, 0xF4, 0xFF),
    "wildcard": QColor(0xE0, 0xE0, 0xE0),
    "expr": QColor(0xFF, 0xF8, 0xE1),
    "wildcard-expr": QColor(0xE0, 0xE0, 0xE0),
}


class QFuzzyPatternNode(QCachedGraphicsItem):
    """One pattern node on the canvas: a leaf statement, or an expression node under
    an expanded leaf. Click selects it; double-click expands a leaf or toggles an
    expression's wildcard."""

    HORIZONTAL_PADDING = 6
    VERTICAL_PADDING = 4

    def __init__(self, view: FuzzyPatternView, path: NodePath, node: PatternNode, kind: str) -> None:
        super().__init__()
        self._view = view
        self.path = path
        self.node = node
        #: "required" | "optional" | "wildcard" for a leaf, "expr" | "wildcard-expr" for an expression
        self.kind = kind
        self.addr = 0  # GraphLayouter sorts nodes by this
        self._title = QGraphicsSimpleTextItem(describe(node), self)
        self._title.setFont(Conf.symexec_font)
        self._title.setPos(self.HORIZONTAL_PADDING, self.VERTICAL_PADDING)
        self._detail: QGraphicsSimpleTextItem | None = None
        detail = self._detail_text()
        if detail:
            self._detail = QGraphicsSimpleTextItem(detail, self)
            self._detail.setFont(Conf.symexec_font)
            self._detail.setBrush(QColor(0x70, 0x70, 0x70))
            self._detail.setPos(
                self.HORIZONTAL_PADDING, self.VERTICAL_PADDING + self._title.boundingRect().height() + 2
            )
        self._update_size()
        self.setAcceptHoverEvents(True)

    @property
    def selected(self) -> bool:
        return self._view.selected_path == self.path

    def _detail_text(self) -> str:
        node = self.node
        if self.kind in ("required", "optional", "wildcard"):
            weight = node.weight  # type: ignore[union-attr]
            parts = [self.kind]
            if weight != 1.0:
                parts.append(f"weight {weight:g}")
            if isinstance(node, PAnyStmt):
                return ", ".join(parts)
            if self.path in self._view.expanded:
                parts.append("expanded")
            return ", ".join(parts)
        return ""

    #
    # events
    #

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._view.select_node(self.path)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._view.activate_node(self.path)
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def hoverEnterEvent(self, event) -> None:  # pylint:disable=unused-argument
        self._view.hovered_block = self
        self._view.redraw_graph()

    def hoverLeaveEvent(self, event) -> None:  # pylint:disable=unused-argument
        self._view.hovered_block = None
        self._view.redraw_graph()

    #
    # painting
    #

    @property
    def failed(self) -> bool:
        """The leaf failed verification in the occurrence selected in the match table."""
        is_leaf = self.kind in ("required", "optional", "wildcard")
        return is_leaf and self._view.leaf_index(self.path) in self._view.failed_leaves

    def paint(self, painter, option, widget) -> None:  # pylint:disable=unused-argument
        painter.setBrush(_FILL[self.kind])
        if self.failed:
            pen = QPen(QColor(0xC0, 0x30, 0x30), 2.5 if self.selected else 2.0)
        elif self.selected:
            pen = QPen(QColor(0x30, 0x60, 0xC0), 2.0)
        else:
            pen = QPen(QColor(0x80, 0x80, 0x80), 1.0)
        painter.setPen(pen)
        painter.drawRoundedRect(QRectF(0, 0, self.width, self.height), 4, 4)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    def _update_size(self) -> None:
        width = self._title.boundingRect().width()
        height = self._title.boundingRect().height()
        if self._detail is not None:
            width = max(width, self._detail.boundingRect().width())
            height += self._detail.boundingRect().height() + 2
        self._width = max(40.0, width + self.HORIZONTAL_PADDING * 2)
        self._height = height + self.VERTICAL_PADDING * 2
        self.recalculate_size()


class QFuzzyPatternArrow(QGraphArrow):
    """An edge between pattern nodes; highlighted when either end is hovered."""

    def __init__(self, view: FuzzyPatternView, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._view = view

    def _should_highlight(self) -> bool:
        hovered = self._view.hovered_block
        return hovered is not None and (hovered is self.edge.src or hovered is self.edge.dst)


class QFuzzyPatternGraph(QZoomableDraggableGraphicsView):
    """The pattern as a graph of nodes, laid out top-down."""

    LEFT_PADDING = 1000
    TOP_PADDING = 1000

    def __init__(self, view: FuzzyPatternView, parent=None) -> None:
        super().__init__(parent=parent)
        self._view = view
        self._graph: networkx.DiGraph | None = None
        self.blocks: set[QFuzzyPatternNode] = set()
        self._edges: list[Edge] = []
        self._arrows: list[QFuzzyPatternArrow] = []

    @property
    def graph(self) -> networkx.DiGraph | None:
        return self._graph

    @graph.setter
    def graph(self, v: networkx.DiGraph | None) -> None:
        self._graph = v
        self.request_relayout()

    def refresh(self) -> None:
        scene = self.scene()
        if scene is not None:
            scene.update(self.sceneRect())

    def request_relayout(self) -> None:
        self._reset_scene()
        self._arrows.clear()
        self.blocks.clear()
        if self._graph is None or self._graph.number_of_nodes() == 0:
            return
        node_sizes: dict[Any, tuple[float, float]] = {}
        for node in self._graph.nodes():
            self.blocks.add(node)
            node_sizes[node] = (node.width, node.height)
        layouter = GraphLayouter(
            self._graph,
            node_sizes,
            node_sorter=lambda nodes: nodes,
            x_margin=6,
            y_margin=6,
            row_margin=12,
            col_margin=12,
        )
        self._edges = layouter.edges
        scene = self.scene()
        for node, (x, y) in layouter.node_coordinates.items():
            scene.addItem(node)
            node.setPos(x, y)
        for edge in self._edges:
            arrow = QFuzzyPatternArrow(self._view, edge, arrow_location="end", arrow_direction="down")
            self._arrows.append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))
        self._reset_view()

    def _initial_position(self):
        return self.scene().itemsBoundingRect().center()
