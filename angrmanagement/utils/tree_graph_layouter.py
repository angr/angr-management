from typing import Dict, Any, Optional, List, Tuple, Set

import networkx

from .edge import Edge


class Direction:
    TOP = 0
    BOTTOM = 1
    BOTH = 2


class TreeGraphEdgeRouter:
    def __init__(self,
                 layers: List[List[Any]],
                 layer_widths: List[float],
                 graph: networkx.DiGraph,
                 node_coordinates: Dict[Any,Tuple[float,float]],
                 node_sizes: Dict[Any,Tuple[float,float]],
                 ):
        self.layers = layers
        self.layer_widths = layer_widths
        self.graph = graph
        self.node_coordinates = node_coordinates
        self.node_sizes = node_sizes

        self.edges = [ ]

        self._route()

    def _route(self):
        curr_x = 0
        for i, layer in enumerate(self.layers):
            curr_x += self.layer_widths[i] + TreeGraphLayouter.HORIZONTAL_SPACING
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
                        x = curr_x - 45
                        edge.add_coordinate(x, y_start)
                        edge.add_coordinate(x, y_end)
                        x = x1
                        edge.add_coordinate(x, y_end)

                    self.edges.append(edge)


class TreeGraphLayouter:
    """
    Vertically (not implemented right now) or horizontally layout a tree-like graph.
    """

    HORIZONTAL_SPACING = 145
    VERTICAL_SPACING = 15

    def __init__(self, graph: networkx.DiGraph, node_sizes: Dict[Any,Tuple[float,float]],
                 initial_nodes: Optional[List[Any]]=None,
                 direction: int=Direction.BOTH,
                 top_limit: Optional[int]=None,
                 bottom_limit: Optional[int]=None,
                 ):
        self._graph = graph
        self._node_sizes = node_sizes

        self._initial_nodes = initial_nodes
        self._top_limit = top_limit
        self._bottom_limit = bottom_limit
        self._direction = direction

        self.node_coordinates: Dict[Any,Tuple[float,float]] = { }
        self.edges = [ ]

        self._layout()

    def _layout(self):

        layers: List[List[Any]] = [ ]

        if not self._initial_nodes:
            # use root nodes as the initial nodes
            # assuming root nodes are not within any loop
            initial_nodes = [ n for n in self._graph.nodes() if self._graph.out_degree[n] == 0 ]
        else:
            initial_nodes = self._initial_nodes

        layers.append(initial_nodes)
        existing_nodes: Set[Any] = set(initial_nodes)

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
                layers.insert(0, new_layer)
                last_layer = new_layer

        if self._direction in (Direction.TOP, Direction.BOTH):
            # expand to include predecessors
            i = 0
            last_layer = layers[-1]
            while self._top_limit is None or i < self._top_limit:
                i += 1
                new_layer = [ ]
                for node in last_layer:
                    for pred in self._graph.predecessors(node):
                        if pred not in existing_nodes:
                            new_layer.append(pred)
                            existing_nodes.add(pred)
                if not new_layer:
                    break
                layers.append(new_layer)
                last_layer = new_layer

        # layout each layer, from root nodes to leaves
        layer_widths = [ ]
        x, y = 0.0, 0.0
        for layer in layers:
            layer_width, layer_height = self._layout_layer(x, y, layer)
            x += layer_width + self.HORIZONTAL_SPACING
            y = 0.0
            layer_widths.append(layer_width)

        # edges
        self.edges = TreeGraphEdgeRouter(layers, layer_widths, self._graph, self.node_coordinates,
                                         self._node_sizes).edges

    def _layout_layer(self, x, y, nodes) -> Tuple[float,float]:
        """
        Layout a layer of nodes.
        """
        max_width, max_height = 0.0, 0.0

        # calculate max width and max height
        for node in nodes:
            width_, height_ = self._node_sizes[node]
            if width_ > max_width:
                max_width = width_
            if height_ > max_height:
                max_height = height_

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
            curr_y = y_ + height_ + self.VERTICAL_SPACING

        return max_width, curr_y
