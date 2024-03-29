from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import networkx

from .edge import Edge


class Direction:
    TOP = 0
    BOTTOM = 1
    BOTH = 2


class TreeGraphEdgeRouter:
    def __init__(
        self,
        layers: list[list[Any]],
        vertical: bool,
        layer_widths: list[float],  # used if vertical is False
        layer_heights: list[float],  # used if vertical is True
        graph: networkx.DiGraph,
        node_coordinates: dict[Any, tuple[float, float]],
        node_sizes: dict[Any, tuple[float, float]],
        horizontal_spacing: int,
        vertical_spacing: int,
    ) -> None:
        self.layers = layers
        self.vertical = vertical
        self.layer_widths = layer_widths
        self.layer_heights = layer_heights
        self.graph = graph
        self.node_coordinates = node_coordinates
        self.node_sizes = node_sizes
        self.horizontal_spacing = horizontal_spacing
        self.vertical_spacing = vertical_spacing

        self.edges = []

        if self.vertical:
            self._route_vertical()
        else:
            self._route_horizontal()

    def _route_vertical(self) -> None:
        curr_y = 0
        for i, layer in enumerate(self.layers):
            curr_y += self.layer_heights[i] + self.vertical_spacing
            for src in layer:
                x0, y0 = self.node_coordinates[src]
                src_width, src_height = self.node_sizes[src]
                for dst in self.graph.successors(src):
                    x1, y1 = self.node_coordinates[dst]
                    # TODO: Right now there is no going back. This should be fixed to handle loops
                    if y0 >= y1:
                        continue
                    dst_width = self.node_sizes[dst][0]
                    edge = Edge(src, dst)
                    x_start = x0 + src_width / 2
                    x_start += 3  # half of the width of the arrow
                    y_start = y0 + src_height
                    x_end = x1 + dst_width / 2
                    y_end = y1 - 6  # height of the arrow
                    if x_start == x_end:
                        # just draw a straight line
                        edge.add_coordinate(x_start, y_start)
                        edge.add_coordinate(x1, y_end)
                    else:
                        # segment line
                        edge.add_coordinate(x_start, y_start)
                        y = curr_y - self.vertical_spacing / 2
                        edge.add_coordinate(x_start, y)
                        edge.add_coordinate(x_end, y)
                        edge.add_coordinate(x_end, y_end)

                    self.edges.append(edge)

    def _route_horizontal(self) -> None:
        curr_x = 0
        for i, layer in enumerate(self.layers):
            curr_x += self.layer_widths[i] + self.horizontal_spacing
            for src in layer:
                x0, y0 = self.node_coordinates[src]
                src_width, src_height = self.node_sizes[src]
                for dst in self.graph.predecessors(src):
                    x1, y1 = self.node_coordinates[dst]
                    # TODO: Right now there is no going back. This should be fixed to handle loops
                    if x0 >= x1:
                        continue
                    dst_height = self.node_sizes[dst][1]
                    edge = Edge(src, dst)
                    x_start = x0 + src_width
                    x_start += 6  # width of the arrow
                    y_start = y0 + src_height / 2
                    y_end = y1 + dst_height / 2
                    if y_start == y_end:
                        # just draw a straight line
                        edge.add_coordinate(x_start, y_start)
                        edge.add_coordinate(x1, y_end)
                    else:
                        # segment line
                        edge.add_coordinate(x_start, y_start)
                        x = curr_x - self.horizontal_spacing / 2
                        edge.add_coordinate(x, y_start)
                        edge.add_coordinate(x, y_end)
                        x = x1
                        edge.add_coordinate(x, y_end)

                    self.edges.append(edge)


class TreeGraphLayouter:
    """
    Vertically or horizontally layout a tree-like graph.
    """

    def __init__(
        self,
        graph: networkx.DiGraph,
        node_sizes: dict[Any, tuple[float, float]],
        initial_nodes: list[Any] | None = None,
        vertical: bool = False,
        direction: int = Direction.BOTH,
        top_limit: int | None = None,
        bottom_limit: int | None = None,
        horizontal_spacing: int = 145,
        vertical_spacing: int = 15,
        layer_sorter=None,
    ) -> None:
        self._graph = graph
        self._node_sizes = node_sizes

        self._initial_nodes = initial_nodes
        self._top_limit = top_limit
        self._bottom_limit = bottom_limit
        self._direction = direction
        self._vertical = vertical
        self.horizontal_spacing = horizontal_spacing
        self.vertical_spacing = vertical_spacing
        self._layer_sorter = layer_sorter

        self.node_coordinates: dict[Any, tuple[float, float]] = {}
        self.edges = []

        self._layout()

    def _layout(self) -> None:
        layers: list[list[Any]] = []

        if not self._initial_nodes:
            # use root nodes as the initial nodes
            # assuming root nodes are not within any loop
            initial_nodes = [n for n in self._graph.nodes() if self._graph.out_degree[n] == 0]
        else:
            initial_nodes = self._initial_nodes

        layers.append(initial_nodes)
        existing_nodes: set[Any] = set(initial_nodes)

        if self._direction in (Direction.BOTTOM, Direction.BOTH):
            # expand to include successors
            i = 0
            last_layer = layers[0]
            while self._bottom_limit is None or i < self._bottom_limit:
                i += 1
                new_layer = []
                for node in last_layer:
                    for succ in self._graph.successors(node):
                        if succ not in existing_nodes:
                            new_layer.append(succ)
                            existing_nodes.add(succ)
                if not new_layer:
                    break
                if self._layer_sorter:
                    new_layer = self._layer_sorter(new_layer)
                layers.insert(0, new_layer)
                last_layer = new_layer

        if self._direction in (Direction.TOP, Direction.BOTH):
            # expand to include predecessors
            i = 0
            last_layer = layers[-1]
            while self._top_limit is None or i < self._top_limit:
                i += 1
                new_layer = []
                for node in last_layer:
                    for pred in self._graph.predecessors(node):
                        if pred not in existing_nodes:
                            new_layer.append(pred)
                            existing_nodes.add(pred)
                if not new_layer:
                    break
                if self._layer_sorter:
                    new_layer = self._layer_sorter(new_layer)
                layers.append(new_layer)
                last_layer = new_layer

        # layout each layer, from root nodes to leaves
        layer_widths = []
        layer_heights = []
        x, y = 0.0, 0.0

        if self._vertical:
            # Tree layers are vertically layouted
            layers = layers[::-1]
            for layer in layers:
                layer_width, layer_height = self._layout_layer_vertical(x, y, layer)
                y += layer_height + self.vertical_spacing
                x = 0.0
                layer_heights.append(layer_height)
        else:
            # Tree layers are horizontally layouted
            for layer in layers:
                layer_width, layer_height = self._layout_layer_horizontal(x, y, layer)
                x += layer_width + self.horizontal_spacing
                y = 0.0
                layer_widths.append(layer_width)

        # edges
        self.edges = TreeGraphEdgeRouter(
            layers,
            self._vertical,
            layer_widths,
            layer_heights,
            self._graph,
            self.node_coordinates,
            self._node_sizes,
            self.horizontal_spacing,
            self.vertical_spacing,
        ).edges

    def _max_width_and_height(self, nodes) -> tuple[float, float]:
        max_width, max_height = 0.0, 0.0

        # calculate max width and max height
        for node in nodes:
            width_, height_ = self._node_sizes[node]
            if width_ > max_width:
                max_width = width_
            if height_ > max_height:
                max_height = height_

        return max_width, max_height

    def _layout_layer_vertical(self, x, y, nodes) -> tuple[float, float]:
        """
        Vertically layout a layer of nodes.
        """
        max_width, max_height = self._max_width_and_height(nodes)

        # calculate their coordinates
        curr_x = x

        for node in nodes:
            preds = self._graph.predecessors(node)
            min_x = None
            max_x = None
            for pred in preds:
                if pred in self.node_coordinates:
                    pred_x, _ = self.node_coordinates[pred]
                    if min_x is None or pred_x < min_x:
                        min_x = pred_x
                    if max_x is None or pred_x + self._node_sizes[pred][0] > max_x:
                        max_x = pred_x + pred.width

            width_, height_ = self._node_sizes[node]
            y_ = y + (max_height / 2 - height_ / 2)

            if min_x is None or max_x is None:
                # preds don't exist
                # just give it something
                x_ = curr_x
            else:
                # stay in the middle of the preds
                x_ = min_x + (max_x - min_x) / 2 - width_ / 2
                if x_ < curr_x:
                    x_ = curr_x

            self.node_coordinates[node] = (x_, y_)
            curr_x = x_ + width_ + self.horizontal_spacing

        return curr_x, max_height

    def _layout_layer_horizontal(self, x, y, nodes) -> tuple[float, float]:
        """
        Horizontally layout a layer of nodes.
        """
        max_width, max_height = self._max_width_and_height(nodes)

        # calculate their coordinates
        curr_y = y

        for node in nodes:
            preds = self._graph.predecessors(node)
            min_y = None
            max_y = None
            for pred in preds:
                if pred in self.node_coordinates:
                    _, pred_y = self.node_coordinates[pred]
                    if min_y is None or pred_y < min_y:
                        min_y = pred_y
                    if max_y is None or pred_y + self._node_sizes[pred][1] > max_y:
                        max_y = pred_y + pred.height

            width_, height_ = self._node_sizes[node]
            x_ = x + (max_width / 2 - width_ / 2)

            if min_y is None or max_y is None:
                # preds don't exist
                # just give it something
                y_ = curr_y
            else:
                # stay in the middle of the preds
                y_ = min_y + (max_y - min_y) / 2 - height_ / 2
                if y_ < curr_y:
                    y_ = curr_y

            self.node_coordinates[node] = (x_, y_)
            curr_y = y_ + height_ + self.vertical_spacing

        return max_width, curr_y
