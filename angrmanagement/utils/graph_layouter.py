from collections import defaultdict
from typing import List

import networkx
from angr.analyses.cfg.cfg_utils import CFGUtils

from .edge import Edge, EdgeSort


class EdgeRouter:
    def __init__(self, graph, col_map, row_map, node_locs, max_col, max_row):
        """
        :param networkx.DiGraph graph:  The graph to route edges on.
        """
        self._graph = graph

        self._rows = row_map
        self._cols = col_map
        self._node_locations = node_locs
        self._max_row = max_row
        self._max_col = max_col

        # Mark whether a spot (col, row) is valid or not for putting edges.
        self._edge_valid = None
        # A map between spots (col, row) and all vertical edges at that spot.
        self.vertical_edges = None
        # A map between spots (col, row) and all horizontal edges at that spot.
        self.horizontal_edges = None

        self._in_edges = defaultdict(list)
        self._out_edges = defaultdict(list)

        self.edges = self._route_edges()

    def _route_edges(self):
        """
        Route edges between nodes.

        :return:                       None
        """

        self._prepare_edge_routing()

        edges = []

        for src, dst, data in self._graph.edges(data=True):
            sort = None
            if data.get("type", None) == "exception":
                sort = EdgeSort.EXCEPTION_EDGE
            edge = self._route_edge(src, dst, sort)
            edges.append(edge)

        self._set_in_edge_indices()
        self._set_out_edge_indices()

        return edges

    def _route_edge(self, src, dst, edge_sort=None):
        """
        Find a series of grids to route an edge from the source node to the destination node.

        :param src:         The beginning of the edge to route.
        :param dst:         The end of the edge to route.
        :return:            None
        """

        MOVE_LEFT = 0
        MOVE_RIGHT = 2

        # build the edge
        edge = Edge(src, dst, sort=edge_sort)

        start_col, start_row = self._node_locations[src]
        end_col, end_row = self._node_locations[dst]

        # start from the middle of the block
        start_col += 1
        end_col += 1
        # start from the next row
        start_row += 1

        start_idx = self._assign_edge_to(edge, "vertical", start_col, start_row, 0)
        edge.add_point(start_col, start_row, start_idx)

        if start_row < end_row:
            min_row, max_row = start_row, end_row
        else:
            max_row, min_row = start_row, end_row

        # find a vertical column to route the edge to the target node
        col = start_col
        if self._edge_available(col, min_row, max_row):
            pass
        else:
            offset = 1
            while True:
                if self._edge_available(col + offset, min_row, max_row):
                    col = col + offset
                    break
                if self._edge_available(col - offset, min_row, max_row):
                    col = col - offset
                    break
                offset += 1

        if col != start_col:
            # generate a line to move to the target column

            if start_col < col:
                min_col, max_col = start_col, col
                move = MOVE_RIGHT
            else:
                max_col, min_col = start_col, col
                move = MOVE_LEFT

            idx = self._assign_edge_to(edge, "horizontal", min_col, start_row, max_col - min_col)
            edge.add_point(col, start_row, idx)
            edge.add_move(move)
        else:
            # there will be a horizontal edge even when the beginning column and the target column are the same, since
            # the two blocks may not be aligned.
            _ = self._assign_edge_to(edge, "horizontal", start_col, start_row, 1)
            # however, we do not need to add the point to the edge

        if start_row != end_row:
            # generate a line to move to the target row
            idx = self._assign_edge_to(edge, "vertical", col, min(start_row + 1, end_row), abs(end_row - start_row) + 1)
            edge.add_point(col, end_row, idx)

        if col != end_col:
            # generate a line to move to the target column
            if col < end_col:
                min_col, max_col = col, end_col
                move = MOVE_RIGHT
            else:
                max_col, min_col = col, end_col
                move = MOVE_LEFT
            idx = self._assign_edge_to(edge, "horizontal", min_col, end_row, max_col - min_col)
            edge.add_point(end_col, end_row, idx)
            edge.add_move(move)

            # move downwards
            # in a new grid, we need a new edge index
            idx = self._assign_edge_to(edge, "vertical", end_col, end_row, 0)
            edge.add_point(end_col, end_row, idx)

        self._add_edge(edge)
        # print(src, dst, edge.points)

        return edge

    def _prepare_edge_routing(self):
        """
        Create and initialize necessary data structions for edge routing.

        :return: None
        """

        self._edge_valid = []
        for col in range(self._max_col + 2):
            self._edge_valid.append([True] * (self._max_row + 1))
        for col, row in self._node_locations.values():
            # edges should not overlap with existing nodes
            self._edge_valid[col][row] = False
            self._edge_valid[col + 1][row] = False

        self.vertical_edges = []
        self.horizontal_edges = []

        for col in range(self._max_col + 2):
            v_edges = []
            h_edges = []
            for row in range(self._max_row + 3):
                v_edges.append({})
                h_edges.append({})
            self.vertical_edges.append(v_edges)
            self.horizontal_edges.append(h_edges)

    def _assign_edge_to(self, edge, sort, col, row, blocks, index=None):
        if sort == "vertical":
            d = self.vertical_edges
        elif sort == "horizontal":
            d = self.horizontal_edges
        else:
            raise ValueError('_assign_edge_to(): Unsupported edge sort "%s".' % sort)

        if sort == "vertical":
            if index is None:
                index = self._find_vertical_available_edge_index(col, row, row + blocks)
            for r in range(row, row + blocks + 1):
                d[col][r][index] = edge

        else:  # sort == 'horizontal'
            if index is None:
                index = self._find_horizontal_available_edge_index(col, col + blocks, row)
            for col_ in range(col, col + blocks + 1):
                d[col_][row][index] = edge

        return index

    def _edge_available(self, col, start_row, end_row):
        for i in range(start_row, end_row):
            if not self._edge_valid[col][i]:
                return False
        return True

    def _first_unused_index(self, indices):
        # find the first unused index
        last_i = None
        for i in sorted(indices):
            if last_i is None or i == last_i + 1:
                last_i = i
            else:
                # we found a gap
                return last_i + 1

        return 0 if last_i is None else last_i + 1

    def _find_vertical_available_edge_index(self, col, start_row, end_row):
        # collect all used indices
        indices = set()

        for row in range(start_row, end_row + 1):
            if self.vertical_edges[col][row]:
                indices.update(self.vertical_edges[col][row].keys())

        return self._first_unused_index(indices)

    def _find_horizontal_available_edge_index(self, start_col, end_col, row):
        # collect all used indices
        indices = set()

        for col in range(start_col, end_col + 1):
            if self.horizontal_edges[col][row]:
                indices.update(self.horizontal_edges[col][row].keys())

        return self._first_unused_index(indices)

    def _add_edge(self, edge):
        """
        Add an edge.

        :param Edge edge:   The Edge instance to add.
        :return:            None
        """

        self._out_edges[edge.src].append(edge)
        self._in_edges[edge.dst].append(edge)

    def _set_in_edge_indices(self):
        # assign in-edge indices
        for _, edges in self._in_edges.items():
            max_idx = None

            if len(edges) == 2:
                # sort by their last horizontal move
                edges = sorted(edges, key=lambda edge: edge.last_move, reverse=True)

            for idx, edge in enumerate(edges):
                edge.end_index = idx
                if max_idx is None or idx > max_idx:
                    max_idx = idx
            for edge in edges:
                edge.max_end_index = max_idx

    def _set_out_edge_indices(self):
        for _, edges in self._out_edges.items():
            max_idx = None
            if len(edges) == 2:
                edges = sorted(edges, key=lambda edge: edge.first_move)  # sort by their first horizontal move

            for idx, edge in enumerate(edges):
                edge.start_index = idx
                if max_idx is None or edge.start_index > max_idx:
                    max_idx = edge.start_index
            for edge in edges:
                edge.max_start_index = max_idx


class GraphLayouter:
    """
    Implements a pseudo layered graph layout (Sugiyama graph layout) algorithm.
    """

    def __init__(
        self,
        graph,
        node_sizes,
        node_compare_key=None,
        node_sorter=None,
        x_margin=10,
        y_margin=5,
        row_margin=16,
        col_margin=16,
    ):
        self.graph = graph
        self._node_sizes = node_sizes
        self._node_compare_key = node_compare_key
        self._node_sorter = node_sorter

        if self._node_compare_key and self._node_sorter:
            raise RuntimeError("You cannot provide both node_compare_key and node_sorter.")

        self.x_margin = x_margin
        self.y_margin = y_margin
        self.row_margin = row_margin
        self.col_margin = col_margin

        self._cols = None
        self._rows = None
        self._max_col = None
        self._max_row = None
        self._locations = None

        self._vertical_edges = None
        self._horizontal_edges = None

        self._grid_max_vertical_id = {}
        self._grid_max_horizontal_id = {}
        self._row_to_nodes = {}
        self._row_heights = []
        self._col_widths = []
        self._grid_coordinates = {}

        self.edges: List[Edge] = []
        self.node_coordinates = {}

        self._layout()

    def _layout(self):
        self._initialize()

        # order the nodes
        ordered_nodes = CFGUtils.quasi_topological_sort_nodes(self.graph)

        # conver the graph to an acylic graph
        acyclic_graph = self._to_acyclic_graph(self.graph, ordered_nodes=ordered_nodes)

        # assign row and column to each node
        self._assign_grid_locations(self.graph, acyclic_graph, ordered_nodes=ordered_nodes)

        # edge routing
        edge_router = EdgeRouter(self.graph, self._cols, self._rows, self._locations, self._max_col, self._max_row)
        self.edges = edge_router.edges
        self._vertical_edges = edge_router.vertical_edges
        self._horizontal_edges = edge_router.horizontal_edges

        # determine the maximum index for each grid
        self._set_max_grid_edge_id()

        # determine row and column sizes
        self._make_grids()

        # calculate coordinates of nodes
        self._calculate_coordinates()

    def _initialize(self):
        self._cols = {}
        self._rows = {}
        self._locations = {}

    def _to_acyclic_graph(self, graph, ordered_nodes=None):
        """
        Convert a given DiGraph into an acyclic graph.

        :param networkx.DiGraph graph: The graph to convert.
        :param list ordered_nodes:     A list of nodes sorted in a topological order.
        :return:                       The converted acyclic graph.
        """

        if ordered_nodes is None:
            # take the quasi-topological order of the graph
            ordered_nodes = CFGUtils.quasi_topological_sort_nodes(graph)

        acyclic_graph = networkx.DiGraph()

        # add each node and its edge into the graph
        visited = set()
        for node in ordered_nodes:
            visited.add(node)
            acyclic_graph.add_node(node)
            for successor in graph.successors(node):
                if successor not in visited:
                    acyclic_graph.add_edge(node, successor)

        return acyclic_graph

    def _assign_grid_locations(self, graph, acyclic_graph, ordered_nodes=None):
        """
        Assign locations to each node in the graph in a bottom-up manner.

        :param networkx.DiGraph graph:          The original graph.
        :param networkx.DiGraph acyclic_graph:  The acyclic graph to work on.
        :param list ordered_nodes:      A list of nodes sorted in a topological order.
        :return:                        None
        """

        if ordered_nodes is None:
            # take the quasi-topological order of the graph
            ordered_nodes = CFGUtils.quasi_topological_sort_nodes(acyclic_graph)

        self._assign_rows(graph, acyclic_graph, ordered_nodes)
        self._assign_columns(acyclic_graph)

    def _assign_rows(self, graph, acyclic_graph, ordered_nodes):
        row_to_nodes = defaultdict(list)

        global_max_row = 0

        max_rows = {}

        """
        # assign min row ID top-down
        for node in ordered_nodes:
            if node not in min_rows:
                min_rows[node] = 0
            row = min_rows[node]
            for successor in acyclic_graph.successors_iter(node):
                if successor not in min_rows or min_rows[successor] > row + 1:
                    min_rows[successor] = row + 1
        """

        # assign max row ID using DFS
        for node in ordered_nodes:
            if node not in max_rows:
                max_rows[node] = 0
            row = max_rows[node]
            global_max_row = max(global_max_row, row)
            for successor in acyclic_graph.successors(node):
                if successor not in max_rows or max_rows[successor] < row + 1:
                    max_rows[successor] = row + 1
                    global_max_row = max(global_max_row, row + 1)

        self._max_row = global_max_row

        """
        for node in reversed(ordered_nodes):
            row = 0
            for successor in graph.successors_iter(node):
                succ_row = max_rows.get(successor, None)
                if succ_row is not None and succ_row + 1 > row:
                    row = succ_row + 1
            max_rows[node] = row
            global_max_row = max(global_max_row, row)

        self._max_row = global_max_row

        # invert row IDs
        for node in ordered_nodes:
            max_rows[node] = self._max_row - max_rows[node]
        """

        # determine row ID for each node
        for node in ordered_nodes:
            # we want to push each node as far up as possible, unless it is the return node
            row = max_rows[node]
            self._rows[node] = row
            row_to_nodes[row].append(node)

        for row in row_to_nodes.keys():
            if self._node_compare_key is not None:
                row_to_nodes[row] = sorted(row_to_nodes[row], key=self._node_compare_key)
            elif self._node_sorter is not None:
                row_to_nodes[row] = self._node_sorter(row_to_nodes[row])
            else:
                # TODO: Use a custom comparator for displaying the CFG, too
                row_to_nodes[row] = sorted(row_to_nodes[row], key=lambda n_: n_.addr, reverse=True)

        self._row_to_nodes = row_to_nodes

    def _assign_columns(self, acyclic_graph):
        global_max_col = 0

        # First iteration: assign column ID bottom-up
        for row_idx in reversed(list(self._row_to_nodes.keys())):
            if self._node_compare_key is not None:
                row_nodes = sorted(self._row_to_nodes[row_idx], key=self._node_compare_key)
            elif self._node_sorter is not None:
                row_nodes = self._node_sorter(self._row_to_nodes[row_idx])
            else:
                row_nodes = sorted(self._row_to_nodes[row_idx], key=lambda n: n.addr)

            next_min_col, next_max_col = 1, 2

            for i, node in enumerate(row_nodes):
                successors = acyclic_graph.successors(node)

                min_col, max_col = None, None

                for successor in successors:
                    if successor in self._cols:
                        succ_col = self._cols[successor]
                        if min_col is None or succ_col < min_col:
                            min_col = succ_col
                        if max_col is None or succ_col > max_col:
                            max_col = succ_col + 1

                if min_col is None and max_col is None:
                    min_col, max_col = next_min_col, next_max_col
                else:
                    if min_col < next_min_col:
                        min_col = next_min_col
                    if max_col < next_min_col:
                        max_col = next_min_col + 1

                # now assign a column ID to the current node
                col = (min_col + max_col) // 2
                self._cols[node] = col
                self._locations[node] = (col, row_idx)
                global_max_col = max(global_max_col, col)

                # update min_col and max_col for the next iteration
                if min_col == max_col:
                    next_min_col = max_col + 2
                else:
                    next_min_col = max_col + 1
                next_max_col = next_min_col + 1

        # Second iteration: Adjust column IDs top-down
        for row_idx in self._row_to_nodes.keys():
            row_nodes = self._row_to_nodes[row_idx]

            next_min_col, next_max_col = None, None

            for i, node in enumerate(row_nodes):
                predecessors = list(acyclic_graph.predecessors(node))
                if len(predecessors) < 2:
                    # Not enough predecessors.
                    # update next_min_col and next_max_col
                    col = self._cols[node]
                    next_min_col = max(next_min_col if next_min_col is not None else 0, col + 2)
                    next_max_col = max(next_max_col if next_max_col is not None else 0, col + 3)
                    continue

                min_col, max_col = next_min_col, next_max_col

                for predecessor in predecessors:
                    if predecessor in self._cols:
                        pred_col = self._cols[predecessor]
                        if min_col is None or min_col > pred_col:
                            min_col = pred_col
                        if max_col is None or max_col < pred_col:
                            max_col = pred_col + 1

                # ideally, this node appears in between its predecessors
                col = (min_col + max_col) // 2
                overlap, col = self._detect_overlap(node, col, row_idx, min_col)

                # now assign a column ID to the current node
                self._cols[node] = col
                self._locations[node] = (col, row_idx)

                next_min_col = max_col + 1
                next_max_col = next_min_col + 1

                global_max_col = max(global_max_col, col)

        self._max_col = global_max_col + 1

    def _detect_overlap(self, node, ideal_col, row_idx, min_col):
        """
        Detect if any overlap will be caused if node in row_idx is placed at column col.

        :param node:            The node.
        :param int ideal_col:   The ideal column index.
        :param int row_idx:     The row that the node is placed at.
        :param int min_col:     The left-most acceptable column index for this node.
        :return:                (bool, int|None), where the first value is True if overlap is detected, False otherwise;
                                the second value is the suggested column.
        :rtype:                 tuple
        """

        overlap_detected = False
        suggested_col = min_col  # will only be used if overlap is detected

        # overlap detection
        for samerow_node in sorted(self._row_to_nodes[row_idx], key=lambda n: self._cols[n]):
            if samerow_node is node:
                continue
            samerow_node_col = self._cols[samerow_node]
            if samerow_node_col - 1 <= ideal_col <= samerow_node_col + 1:
                # collision detected :(
                overlap_detected = True
            if samerow_node_col - 1 <= suggested_col <= samerow_node_col + 1:
                # adjust our suggestion, which will be tested in the next iteration
                suggested_col = samerow_node_col + 2
            if overlap_detected and suggested_col < samerow_node_col - 1:
                # amazing, we got a suggestion working!
                # early termination of the loop
                break

        if overlap_detected:
            return True, suggested_col
        else:
            return False, ideal_col

    def _make_grids(self):
        """
        Determine the width of each column and the height of each row.

        :return: None
        """

        self._row_heights = [0] * (self._max_row + 2)
        self._col_widths = [0] * (self._max_col + 2)

        # update grid sizes based on nodes
        for node in self.graph.nodes():
            col, row = self._locations[node]

            width, height = self._node_sizes[node]

            if self._row_heights[row] < height:
                self._row_heights[row] = height

            if self._col_widths[col] < width // 2:
                self._col_widths[col] = width // 2
            if col + 1 < len(self._col_widths) and self._col_widths[col + 1] < width // 2:
                self._col_widths[col + 1] = width // 2

        # update grid sizes based on edges
        for col in range(self._max_col + 2):
            for row in range(self._max_row + 2):
                key = (col, row)
                if key in self._grid_max_vertical_id:
                    col_width = (self._grid_max_vertical_id[key] + 2) * self.x_margin
                    if self._col_widths[col] < col_width:
                        self._col_widths[col] = col_width
                if key in self._grid_max_horizontal_id:
                    row_height = (self._grid_max_horizontal_id[key] + 2) * self.y_margin
                    if self._row_heights[row] < row_height:
                        self._row_heights[row] = row_height

        # the left-most and the right-most column do not have any node assigned to it
        if self._col_widths[0] < 20:
            self._col_widths[0] = 20
        if self._col_widths[-1] < 20:
            self._col_widths[-1] = 20

    def _set_max_grid_edge_id(self):
        """
        For each grid, calculate the maximum edge index for both horizontal edges and vertical edges.

        :return: None
        """

        # horizontal edges
        for col, row_edges in enumerate(self._horizontal_edges):
            for row, edges in enumerate(row_edges):
                if not edges:
                    continue
                key = (col, row)
                self._grid_max_horizontal_id[key] = max(edges.keys())

        # vertical edges
        for col, row_edges in enumerate(self._vertical_edges):
            for row, edges in enumerate(row_edges):
                if not edges:
                    continue
                key = (col, row)
                self._grid_max_vertical_id[key] = max(edges.keys())

    def _calculate_coordinates(self):
        """
        Calculate coordinates for each grid, and then calculate coordinates for each node.

        :return: None
        """

        row_max_ids = {}
        for col, row in self._grid_max_horizontal_id.keys():
            if row not in row_max_ids:
                row_max_ids[row] = self._grid_max_horizontal_id[(col, row)]
            elif self._grid_max_horizontal_id[(col, row)] > row_max_ids[row]:
                row_max_ids[row] = self._grid_max_horizontal_id[(col, row)]

        y = 0
        # calculate the top margin based on the number of horizontal edges above
        top_margin_height = self.row_margin * 2
        if 0 in row_max_ids:
            top_margin_height += self.y_margin * (row_max_ids[0] + 2)
        y += top_margin_height

        for row in range(-1, self._max_row + 2):
            x = 0

            for col in range(-1, self._max_col + 2):
                self._grid_coordinates[(col, row)] = (x, y)
                x += self._col_widths[col] + self.col_margin
            if self._row_heights[row] is None:
                self._row_heights[row] = 0

            # calculate the bottom margin based on the number of horizontal edges below
            bottom_margin_height = self.row_margin * 2
            if (row + 1) in row_max_ids:
                bottom_margin_height += self.y_margin * (row_max_ids[row + 1] + 2)
            y += self._row_heights[row] + bottom_margin_height

        # nodes
        for node in self.graph.nodes():
            col, row = self._locations[node]
            grid_x, grid_y = self._grid_coordinates[(col, row)]
            grid_a_width, grid_b_width = self._col_widths[col], self._col_widths[col + 1]
            grid_height = self._row_heights[row]
            node_width, node_height = self._node_sizes[node]

            self.node_coordinates[node] = (
                grid_x + ((grid_a_width + grid_b_width) // 2 - node_width // 2),
                grid_y + (grid_height // 2 - node_height // 2),
            )

        # edges
        for edge in self.edges:
            src_node_x, src_node_y = self.node_coordinates[edge.src]
            src_node_width, src_node_height = self._node_sizes[edge.src]

            dst_node_x, dst_node_y = self.node_coordinates[edge.dst]
            dst_node_width, dst_node_height = self._node_sizes[edge.dst]

            # dst_node_col, dst_node_row = self._locations[edge.dst]

            # start point
            _, _, start_x_index = edge.points[0]
            start_point_x_base = src_node_x + src_node_width // 2 - (self.x_margin * (edge.max_start_index + 1) // 2)
            start_point_x = self._indexed_x(start_point_x_base, start_x_index)
            start_point = (start_point_x, src_node_y + src_node_height)
            edge.add_coordinate(*start_point)

            prev_col, prev_row = self._locations[edge.src]
            prev_col += 1
            prev_row += 1
            x, y_base = start_point[0], start_point[1] + self.row_margin

            if len(edge.points) > 1:
                next_col, next_row, next_idx = edge.points[1]
                starting_col, starting_row = self._locations[edge.src]
                y_base = self._nointersecting_y(starting_row, starting_col, next_col, default=y_base) + self.row_margin
                y = self._indexed_y(y_base, next_idx)
            else:
                y = y_base

            # add a line that moves downwards from the exit
            edge.add_coordinate(x, y)

            # set previous x and y
            prev_x, prev_y = x, y

            # each point on the edge

            for point_id, (col, row, _) in enumerate(edge.points[1:-1]):
                if col == prev_col:
                    assert row != prev_row
                    # vertical
                    x = prev_x

                    base_y = self._grid_coordinates[(col, row - 1)][1] + self._row_heights[row - 1] + self.row_margin
                    if point_id + 1 == len(edge.points) - 2:
                        y = base_y
                    else:
                        next_col, next_row, next_idx = edge.points[point_id + 1 + 1]
                        y = self._indexed_y(base_y, next_idx)

                elif row == prev_row:
                    assert col != prev_col
                    # horizontal
                    if point_id + 1 == len(edge.points) - 2:
                        base_x = dst_node_x + dst_node_width // 2
                        x = self._indexed_x(base_x, edge.end_index)
                    else:
                        next_col, next_row, next_idx = edge.points[point_id + 1 + 1]
                        base_x = self._grid_coordinates[(col, row)][0]
                        x = self._indexed_x(base_x, next_idx)

                    y = prev_y

                else:
                    # the impossible branch
                    assert False

                edge.add_coordinate(x, y)

                # update prev_*
                prev_col, prev_row = col, row
                prev_x, prev_y = x, y

            # the last point, which is always at the top of the destination node
            base_x = dst_node_x + dst_node_width // 2 - (self.x_margin * (edge.max_end_index + 1) // 2)
            _, _, end_x_index = edge.points[-1]
            x = self._indexed_x(base_x, end_x_index)
            if x != prev_x:
                # add an extra coordinate to move horizontally
                edge.add_coordinate(x, prev_y)
            end_point = (x, dst_node_y - 6)
            edge.add_coordinate(*end_point)

    def _indexed_x(self, base_x, idx):
        return base_x + idx * self.x_margin

    def _indexed_y(self, base_y, idx):
        return base_y + idx * self.y_margin

    def _nointersecting_y(self, row, starting_col, ending_col, default=None):
        """
        Return the correct y coordinate for a point on an edge that will not lead to the following edge segment
        intersect with any node between `min_col` and `max_col`.

        :param int row:             Row of this point.
        :param int starting_col:    The starting column of the next edge segment.
        :param int ending_col:      The ending column of the next edge segment.
        :param float default:       The default y coordinate to use if we fail to determine a desired y coordinate.
        :return:                    The desired y coordinate.
        :rtype:                     float
        """

        max_y = None

        if starting_col < ending_col:
            min_col, max_col = starting_col, ending_col
        else:
            min_col, max_col = ending_col, starting_col

        for col in range(min_col, max_col + 1):
            key = (col, row)
            if key not in self._grid_coordinates:
                continue
            _, y = self._grid_coordinates[key]
            new_y = y + self._row_heights[row]
            if max_y is None or new_y > max_y:
                max_y = new_y

        return max_y if max_y is not None else default
