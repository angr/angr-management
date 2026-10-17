"""
Graphs of boxes without a toolkit: the proximity, dependency, data dependency and pattern graphs and the symbolic
execution path tree.

Each of those Qt views wraps the nodes of an analysis' networkx graph in graphics items and lays them out;
:func:`convert_graph` is that wrapping, shared. :class:`TreeGraphPresenter` is the same for a frontend that draws text:
it takes the analysis graph from ``graph_source``, the lines of each node's box from ``label_builder``, and lays the
boxes out in character cells with :class:`~angrmanagement.utils.graph_layouter.GraphLayouter` or (``layouter="tree"``)
:class:`~angrmanagement.utils.tree_graph_layouter.TreeGraphLayouter`, giving a :class:`GraphPicture`: each box's
position and lines, and each edge as corner points.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import networkx

from angrmanagement.utils.graph_layouter import GraphLayouter
from angrmanagement.utils.tree_graph_layouter import TreeGraphLayouter

from .spans import Line

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

#: GraphLayouter's margins in cells, as the disassembly graph lays out its blocks.
GRAPH_CELL_MARGINS = {
    "x_margin": 2,
    "y_margin": 1,
    "row_margin": 1,
    "col_margin": 2,
    "min_edge_col_width": 4,
    "arrow_gap": 1,
}
#: TreeGraphLayouter's spacing in cells: between layers, and between the boxes of a layer.
TREE_HORIZONTAL_SPACING = 4
TREE_VERTICAL_SPACING = 1
#: The rows between layers of a tree laid out from top to bottom.
TREE_LAYER_ROWS = 3
#: How much wider and taller a box is than its lines: a border and a space on each side.
BOX_PADDING = (4, 2)


def convert_graph(graph: networkx.DiGraph, convert: Callable[[Any, dict], Any]) -> networkx.DiGraph:
    """
    A graph of the same shape as ``graph`` whose nodes are ``convert(node, converted)``, where ``converted`` maps the
    nodes already converted to theirs (so ``convert`` can return the same object twice); a node converted to None is
    left out, with its edges.
    """
    g = networkx.DiGraph()
    converted: dict[Any, Any] = {}
    for node in graph.nodes():
        new = convert(node, converted)
        if new is not None:
            g.add_node(new)
    for src, dst in graph.edges():
        new_src = convert(src, converted)
        new_dst = convert(dst, converted)
        if new_src is not None and new_dst is not None:
            g.add_edge(new_src, new_dst)
    return g


@dataclass(eq=False)
class GraphBox:
    """One node's box: the node, the lines it shows, and the address GraphLayouter orders a row by."""

    node: Any
    lines: list[Line]
    addr: int = 0
    #: the style key of the box's frame and background
    style: str = ""

    @property
    def width(self) -> int:
        return max((line.width for line in self.lines), default=0) + BOX_PADDING[0]

    @property
    def height(self) -> int:
        return len(self.lines) + BOX_PADDING[1]


@dataclass
class GraphEdge:
    """An edge from box ``src`` to box ``dst`` through ``points`` (corner points, the arrow on the last)."""

    src: GraphBox
    dst: GraphBox
    points: list[tuple[int, int]]
    style: str = ""


@dataclass
class GraphPicture:
    """Boxes at their positions and the edges between them, in cells."""

    boxes: list[GraphBox] = field(default_factory=list)
    layout: dict[GraphBox, tuple[int, int]] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    @property
    def size(self) -> tuple[int, int]:
        width = max((x + box.width for box, (x, _y) in self.layout.items()), default=0)
        height = max((y + box.height for box, (_x, y) in self.layout.items()), default=0)
        for edge in self.edges:
            for x, y in edge.points:
                width, height = max(width, x + 1), max(height, y + 1)
        return width, height

    def box_of(self, node: Any) -> GraphBox | None:
        for box in self.boxes:
            if box.node is node:
                return box
        return None

    def box_at(self, x: int, y: int) -> GraphBox | None:
        """The box covering cell (x, y), or None."""
        for box, (bx, by) in self.layout.items():
            if bx <= x < bx + box.width and by <= y < by + box.height:
                return box
        return None


def tree_edges(graph: networkx.DiGraph, layout: dict[Any, tuple[int, int]], vertical: bool) -> list[GraphEdge]:
    """
    The edges of a tree laid out by TreeGraphLayouter, routed in cells: from the middle of the side of the source that
    faces the destination, to the cell before the destination, through the middle of the gap between them.
    TreeGraphLayouter's own router adds the Qt arrow's size in pixels, which a cell layout cannot use.
    """
    edges: list[GraphEdge] = []
    for src, dst in graph.edges():
        if src not in layout or dst not in layout:
            continue
        (sx, sy), (dx, dy) = layout[src], layout[dst]
        if vertical:
            # layers top to bottom; the edge goes down from the source to the destination
            start = (sx + src.width // 2, sy + src.height)
            end = (dx + dst.width // 2, dy - 1)
            if end[1] <= start[1]:
                continue
            mid = (start[1] + end[1]) // 2
            points = [start, (start[0], mid), (end[0], mid), end]
        else:
            # layers right to left (the roots are at the right); an edge goes from the source towards its successor
            start = (sx + src.width, sy + src.height // 2) if dx > sx else (sx - 1, sy + src.height // 2)
            end = (dx - 1, dy + dst.height // 2) if dx > sx else (dx + dst.width, dy + dst.height // 2)
            mid = (start[0] + end[0]) // 2
            points = [start, (mid, start[1]), (mid, end[1]), end]
        edges.append(GraphEdge(src, dst, points))
    return edges


class TreeGraphPresenter:
    """
    A graph of boxes in cells, made from an analysis graph.

    :param graph_source:    Gives the graph to show (None for none).
    :param label_builder:   Gives the lines of a node's box, or a :class:`GraphBox` for it (None leaves it out).
    :param layouter:        ``"graph"`` for GraphLayouter, ``"tree"`` for TreeGraphLayouter.
    :param node_sorter:     Orders the boxes of a GraphLayouter row (a list of :class:`GraphBox` in, out).
    :param vertical:        For the tree layouter: layers from top to bottom instead of right to left.
    """

    def __init__(
        self,
        graph_source: Callable[[], networkx.DiGraph | None],
        label_builder: Callable[[Any], list[Line] | GraphBox | None],
        layouter: str = "graph",
        node_sorter: Callable[[list[GraphBox]], list[GraphBox]] | None = None,
        vertical: bool = False,
    ) -> None:
        self.graph_source = graph_source
        self.label_builder = label_builder
        self.layouter = layouter
        self.node_sorter = node_sorter
        self.vertical = vertical
        self._picture: GraphPicture | None = None
        #: the node the frontend shows as selected
        self.selected: Any = None

    def invalidate(self) -> None:
        """The graph or a label changed: lay it out again when next asked."""
        self._picture = None

    @property
    def picture(self) -> GraphPicture:
        if self._picture is None:
            self._picture = self.build()
        return self._picture

    def _box(self, node: Any, converted: dict) -> GraphBox | None:
        if node in converted:
            return converted[node]
        made = self.label_builder(node)
        box = made if isinstance(made, GraphBox) or made is None else GraphBox(node, made)
        converted[node] = box
        return box

    def build(self) -> GraphPicture:
        graph = self.graph_source()
        if graph is None or graph.number_of_nodes() == 0:
            return GraphPicture()
        boxes = convert_graph(graph, self._box)
        sizes = {box: (box.width, box.height) for box in boxes.nodes()}
        picture = GraphPicture(boxes=list(boxes.nodes()))
        if self.layouter == "tree":
            tl = TreeGraphLayouter(
                boxes,
                sizes,
                vertical=self.vertical,
                horizontal_spacing=TREE_HORIZONTAL_SPACING,
                # layers stacked from top to bottom need rows between them for the edges
                vertical_spacing=TREE_LAYER_ROWS if self.vertical else TREE_VERTICAL_SPACING,
            )
            raw = {box: (int(x), int(y)) for box, (x, y) in tl.node_coordinates.items()}
            # the tree layouter puts its first layer at the origin and others at negative offsets: move all in view
            min_x = min((x for x, _y in raw.values()), default=0)
            min_y = min((y for _x, y in raw.values()), default=0)
            picture.layout = {box: (x - min_x + 1, y - min_y + 1) for box, (x, y) in raw.items()}
            picture.boxes = [box for box in picture.boxes if box in picture.layout]
            picture.edges = tree_edges(boxes, picture.layout, self.vertical)
            return picture
        gl = GraphLayouter(boxes, sizes, node_sorter=self.node_sorter, **GRAPH_CELL_MARGINS)
        picture.layout = {box: (int(x), int(y)) for box, (x, y) in gl.node_coordinates.items()}
        picture.edges = [
            GraphEdge(edge.src, edge.dst, [(int(x), int(y)) for x, y in edge.coordinates]) for edge in gl.edges
        ]
        return picture

    def nodes(self) -> list[Any]:
        """The nodes shown, top to bottom and left to right."""
        picture = self.picture
        ordered = sorted(picture.layout.items(), key=lambda item: (item[1][1], item[1][0]))
        return [box.node for box, _pos in ordered]

    def select_next(self, delta: int) -> Any:
        """Select the next (or, for a negative ``delta``, the previous) node in reading order; returns it."""
        nodes = self.nodes()
        if not nodes:
            self.selected = None
            return None
        idx = nodes.index(self.selected) if self.selected in nodes else (-1 if delta > 0 else 0)
        self.selected = nodes[(idx + delta) % len(nodes)]
        return self.selected


def text_lines(texts: Iterable[str], style: str = "") -> list[Line]:
    """One line of one span per text."""
    return [Line().append(text, style) for text in texts]


__all__ = [
    "GRAPH_CELL_MARGINS",
    "GraphBox",
    "GraphEdge",
    "GraphPicture",
    "TreeGraphPresenter",
    "convert_graph",
    "text_lines",
    "tree_edges",
]
