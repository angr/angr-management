from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.known_patterns import PAnyStmt, dsl
from angr.analyses.decompiler.known_patterns.edit import describe
from PySide6.QtCore import QPoint, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QPen, QTransform
from PySide6.QtWidgets import QGraphicsSimpleTextItem, QMenu

from angrmanagement.config import Conf
from angrmanagement.utils.graph_layouter import GraphLayouter

from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QGraphArrow
from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    import networkx
    from angr.analyses.decompiler.known_patterns import PatternNode
    from angr.analyses.decompiler.known_patterns.edit import NodePath

    from angrmanagement.ui.views.pattern_view import PatternView
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


def _bytes(n: int) -> str:
    return f"{n} byte" if n == 1 else f"{n} bytes"


def _callee(names: frozenset[str]) -> str:
    return "|".join(sorted(names)) or "*"


def node_label(node: PatternNode) -> str:
    """The AIL class a node matches, then what it constrains; describe() for the rest."""
    if isinstance(node, dsl.PAnyStmt):
        label = "Statement (any)"
    elif isinstance(node, dsl.PAssign):
        label = "Assignment"
    elif isinstance(node, dsl.PStore):
        label = "Store" + (f" {_bytes(node.size)}" if node.size is not None else "")
    elif isinstance(node, dsl.PCallStmt):
        label = "Call " + _callee(node.call.names)
    elif isinstance(node, dsl.PCondJump):
        label = "ConditionalJump"
    elif isinstance(node, dsl.PReturn):
        label = "Return" if node.values is not None else "Return (any values)"
    elif isinstance(node, dsl.PAny):
        label = "Expression (any)"
    elif isinstance(node, dsl.PVVar):
        label = "VirtualVariable" + (f" {node.bits} bits" if node.bits is not None else "")
    elif isinstance(node, dsl.PConst):
        if node.symbol is not None:
            label = f"Const &{node.symbol}"
        elif node.value is not None:
            label = f"Const {node.value:#x}" if node.value >= 0 else f"Const {node.value}"
        else:
            label = "Const (any)"
    elif isinstance(node, (dsl.PBinOp, dsl.PUnaryOp)):
        ops = node.op if isinstance(node.op, str) else "|".join(sorted(node.op))
        label = f"{'BinaryOp' if isinstance(node, dsl.PBinOp) else 'UnaryOp'} {ops}"
    elif isinstance(node, dsl.PLoad):
        label = "Load" + (f" {_bytes(node.size)}" if node.size is not None else "")
    elif isinstance(node, dsl.PConv):
        sizes = f" {node.from_bits} to {node.to_bits} bits" if node.from_bits and node.to_bits else ""
        label = "Convert" + sizes
    elif isinstance(node, dsl.PExtract):
        label = "Extract" + (f" {node.bits} bits" if node.bits is not None else "")
    elif isinstance(node, dsl.PCall):
        label = "Call " + _callee(node.names)
    elif isinstance(node, dsl.PPhi):
        label = "Phi"
    elif isinstance(node, dsl.PITE):
        label = "ITE"
    else:
        return describe(node)
    name = getattr(node, "name", None)
    return f"{label} [{name}]" if name else label


class QPatternNode(QCachedGraphicsItem):
    """One pattern node on the canvas: a leaf statement, or an expression node under
    one. Click selects it; double-click expands or collapses its subtree."""

    HORIZONTAL_PADDING = 6
    VERTICAL_PADDING = 4

    def __init__(self, view: PatternView, path: NodePath, node: PatternNode, kind: str) -> None:
        super().__init__()
        self._view = view
        self.path = path
        self.node = node
        #: "required" | "optional" | "wildcard" for a leaf, "expr" | "wildcard-expr" for an expression
        self.kind = kind
        self.addr = 0  # GraphLayouter sorts nodes by this
        self._title = QGraphicsSimpleTextItem(node_label(node), self)
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
            if self.path in self._view.collapsed:
                parts.append("collapsed")
            return ", ".join(parts)
        if self.path in self._view.collapsed:
            return "collapsed"
        return ""

    #
    # events
    #

    def mousePressEvent(self, event) -> None:
        # a release only reaches the item that accepted the press
        if event.button() == Qt.MouseButton.LeftButton:
            event.accept()
            return
        super().mousePressEvent(event)

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


class QPatternArrow(QGraphArrow):
    """An edge between pattern nodes; highlighted when either end is hovered."""

    def __init__(self, view: PatternView, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._view = view

    def _should_highlight(self) -> bool:
        hovered = self._view.hovered_block
        return hovered is not None and (hovered is self.edge.src or hovered is self.edge.dst)


class QPatternGraph(QZoomableDraggableGraphicsView):
    """The pattern as a graph of nodes, laid out top-down."""

    LEFT_PADDING = 1000
    TOP_PADDING = 1000

    def __init__(self, view: PatternView, parent=None) -> None:
        super().__init__(parent=parent)
        self._view = view
        self._graph: networkx.DiGraph | None = None
        self.blocks: set[QPatternNode] = set()
        self._edges: list[Edge] = []
        self._arrows: list[QPatternArrow] = []

    @property
    def graph(self) -> networkx.DiGraph | None:
        return self._graph

    def context_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.addAction("Expand all", self._view.expand_all)
        menu.addAction("Collapse all", self._view.collapse_all)
        return menu

    def contextMenuEvent(self, event) -> None:
        self.context_menu().exec(event.globalPos())
        event.accept()

    @graph.setter
    def graph(self, v: networkx.DiGraph | None) -> None:
        self.set_graph(v)

    def set_graph(self, graph: networkx.DiGraph | None, anchor: NodePath | None = None) -> None:
        """Show ``graph``. With ``anchor``, the node at that path stays where it is on screen, at
        the same zoom; without one, or when it was not shown, the view centers on the tree."""
        keep = None
        old = next((b for b in self.blocks if b.path == anchor), None) if anchor is not None else None
        if old is not None and old.scene() is self.scene():
            keep = (anchor, self.mapFromScene(old.scenePos()), self.transform())
        self._graph = graph
        self.request_relayout(keep)

    def refresh(self) -> None:
        scene = self.scene()
        if scene is not None:
            scene.update(self.sceneRect())

    def request_relayout(self, keep: tuple[NodePath, QPoint, QTransform] | None = None) -> None:
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
            arrow = QPatternArrow(self._view, edge, arrow_location="end", arrow_direction="down")
            self._arrows.append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))
        # a scene's rect only ever grows on its own; a stale, larger one pulls the view off the tree
        scene.setSceneRect(
            scene.itemsBoundingRect().adjusted(
                -self.LEFT_PADDING, -self.TOP_PADDING, self.LEFT_PADDING, self.TOP_PADDING
            )
        )
        new = next((b for b in self.blocks if b.path == keep[0]), None) if keep is not None else None
        if new is None:
            self._reset_view()
            return
        self.setTransform(keep[2])
        delta = self.mapFromScene(new.scenePos()) - keep[1]
        self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() + delta.x())
        self.verticalScrollBar().setValue(self.verticalScrollBar().value() + delta.y())

    def _initial_position(self):
        return self.scene().itemsBoundingRect().center()

    def _reset_view(self) -> None:
        # keep the zoom, then center; the base class's restore zooms about a misplaced anchor
        self.resetTransform()
        if self.zoom_factor:
            self.scale(self.zoom_factor, self.zoom_factor)
        self.centerOn(self._initial_position())
