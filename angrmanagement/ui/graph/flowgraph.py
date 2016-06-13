
from collections import defaultdict

import pygraphviz
import networkx

from atom.api import List, Typed, ForwardTyped, observe
from enaml.widgets.api import Container
from enaml.widgets.frame import Frame
from enaml.core.declarative import d_
from enaml.qt.QtGui import QPainterPath
from enaml.qt.QtCore import QPointF, QRectF
from enaml.qt.qt_container import QtContainer

from .utils import grouper
from .graph import QtGraph, ProxyGraph

class QtFlowGraph(QtGraph):
    declaration = ForwardTyped(lambda: FlowGraph)

    def _compute_node_locations(self, start):
        """
        Compute coordinates for all CFG nodes in the view

        :param int start: The starting address
        :return: a mapping between nodes' names and their coordinates
        :rtype: dict
        """

        coordinates = {}
        node_map = {}

        # Create the map
        for child in self.children():
            if not isinstance(child, QtContainer):
                continue
            node_map[child.declaration.addr] = child

        g = networkx.DiGraph()
        for s, d in self.declaration.edges:
            g.add_edge(int(s), int(d))
        for child in self.children():
            g.add_node(child.declaration.addr)

        # order the children
        zero_indegree_nodes = [ s for s in g.nodes_iter() if g.in_degree(s) == 0 and s != start ]
        sources = [ start ] + zero_indegree_nodes
        all_children = []

        for s in sources:
            if not s in g:
                continue

            bfs_successors = networkx.bfs_successors(g, s)

            stack = [s]

            while stack:
                n = stack[0]
                stack = stack[1:]

                if n not in all_children:
                    all_children.append(n)
                if n in bfs_successors:
                    for suc in bfs_successors[n]:
                        if suc not in all_children:
                            all_children.append(suc)
                            stack.append(suc)

        for child in all_children:

            node = node_map[child]
            addr = node.declaration.addr
            width, height = node._layout_manager.best_size()

            # Get its predecessors and successors
            predecessors = [ ] if addr not in g else g.predecessors(addr)
            successors = [ ] if addr not in g else g.successors(addr)

            if addr in coordinates:
                x, y = coordinates[addr]
            else:
                x, y = None, None

            if x is None:
                x = 0

            # this node must stay lower than all of its predecessors if addresses of those predecessors come before this
            # node
            for p in predecessors:
                if p < addr and p in coordinates:
                    new_y = coordinates[p][1] + 50
                    y = new_y if (y is None or new_y > y) else y

            # is y determined?
            if y is None:
                # nope
                # let's check all successors
                for s in successors:
                    if s > addr and s in coordinates:
                        new_y = coordinates[s][1] - 50 - height
                        y = new_y if (y is None or new_y > y) else y

            # is y determined?
            if y is None:
                # nope...
                # it gotta be something
                y = 0

            coordinates[addr] = (x, y)

            # let's layout all of its predecessors
            # TODO:

            # all its successors must stay below it if addresses of those successors come after this node
            for s in successors:
                if s > addr:
                    s_y = y + height + 50
                    if s in coordinates:
                        if coordinates[s][1] < s_y:
                            coordinates[s] = (coordinates[s][0], s_y)
                    else:
                        coordinates[s] = (None, s_y)

            # horizontally distribute all its successors
            successors_after = [s for s in successors if s > addr]
            if len(successors_after) >= 1:
                all_width = [node_map[s]._layout_manager.best_size()[0] for s in successors_after]
                total_width = sum(all_width) + 50 * (len(all_width) - 1)

                # from left to right
                leftmost_x = x + width / 2 - total_width / 2

                for s in successors_after:
                    s_node = node_map[s]
                    s_width, _ = s_node._layout_manager.best_size()
                    s_x = leftmost_x
                    leftmost_x += s_width + 50

                    if s in coordinates:
                        if coordinates[s][0] is None:
                            coordinates[s] = (s_x, coordinates[s][1])
                    else:
                        coordinates[s] = (s_x, None)

        for k in coordinates.keys():
            if coordinates[k][0] is None:
                coordinates[k] = (0, coordinates[k][1])
            if coordinates[k][1] is None:
                coordinates[k] = (coordinates[k][0], 0)

        return coordinates

    def _compute_edge_locations(self, node_coordinates, edges):

        node_map = {}
        edge_coordinates = [ ]

        # Create the map
        for child in self.children():
            if not isinstance(child, QtContainer):
                continue
            node_map[child.declaration.addr] = child

        for src_addr_str, dst_addr_str in edges:
            src_addr = int(src_addr_str)
            dst_addr = int(dst_addr_str)

            src_node = node_map[src_addr]
            src_width, src_height = src_node._layout_manager.best_size()
            src_x, src_y = node_coordinates[src_addr]

            dst_node = node_map[dst_addr]
            dst_width, dst_height = dst_node._layout_manager.best_size()
            dst_x, dst_y = node_coordinates[dst_addr]

            if src_node is not dst_node:
                start_point = (src_x + src_width / 2, src_y + src_height)
                end_point = (dst_x + dst_width / 2, dst_y)

                edge_coordinates.append((start_point, end_point))

            else:
                # TODO
                pass

        return edge_coordinates

    def request_relayout(self):
        # y = 0.0

        # for child in self.children():
        #     if not isinstance(child, QtContainer):
        #         continue
        #     scene_proxy = self._proxies[child]
        #     width, height = child._layout_manager.best_size()
        #     scene_proxy.setPos(0.0, y)
        #     y += height + 25.0

        # Remove all paths
        for p in self._edge_paths:
            self.scene.removeItem(p)
        self._edge_paths = []

        children_names = {child.declaration.name for child in self.children() if isinstance(child, QtContainer)}

        if any(from_ not in children_names or to not in children_names for (from_, to) in self.declaration.edges):
            # hasn't finished being set up yet
            return

        for child in self.children():
            if not isinstance(child, QtContainer):
                continue
            scene_proxy = self._proxy(child)
            width, height = child._layout_manager.best_size()
            scene_proxy.setGeometry(QRectF(0.0, 0.0, width, height))

        coordinates = self._compute_node_locations(self.declaration.func_addr)

        for child in self.children():
            if not isinstance(child, QtContainer):
                continue
            """
            scene_proxy = self._proxies[child]
            node = g.get_node(child.declaration.name)
            center_x, center_y = (-float(v)/72.0 for v in node.attr['pos'].split(','))
            width, height = child._layout_manager.best_size()
            x = center_x - (width / 2.0)
            y = center_y - (height / 2.0)
            scene_proxy.setPos(x, y)
            """
            scene_proxy = self._proxies[child]
            # width, height = child._layout_manager.best_size()
            x, y = coordinates[child.declaration.addr]
            scene_proxy.setPos(x, y)

        edge_coordinates = self._compute_edge_locations(coordinates, self.declaration.edges)

        for from_, to in edge_coordinates:
            painter = QPainterPath(QPointF(*from_))
            painter.lineTo(QPointF(*to))
            p = self.scene.addPath(painter)
            self._edge_paths.append(p)

        """
        for from_, to in edge_coordinates:
            if from_ not in children_names or to not in children_names:
                continue
            edge = g.get_edge(from_, to)
            # TODO: look at below code
            all_points = [tuple(-float(v) / 72.0 for v in t.strip('e,').split(',')) for t in
                          edge.attr['pos'].split(' ')]
            arrow = all_points[0]
            start_point = all_points[1]

            painter = QPainterPath(QPointF(*start_point))
            for c1, c2, end in grouper(all_points[2:], 3):
                painter.cubicTo(QPointF(*c1), QPointF(*c2), QPointF(*end))

            self._edge_paths.append(self.scene.addPath(painter))
        """

        rect = self.scene.itemsBoundingRect()
        # Enlarge the rect so there is enough room at right and bottom
        rect.setX(rect.x() - self.LEFT_PADDING)
        rect.setY(rect.y() - self.TOP_PADDING)
        rect.setWidth(rect.width() + 2 * self.LEFT_PADDING)
        rect.setHeight(rect.height() + 2 * self.TOP_PADDING)

        self.scene.setSceneRect(rect)
        self.widget.viewport().update()

        self.show_selected()

class FlowGraph(Frame):

    supergraph = d_(Typed(networkx.DiGraph))

    #: The edges (as names) of the Graph
    edges = d_(List())

    #: The "selected" node that should be visible
    selected = d_(Typed(str))

    func_addr = d_(Typed(int))

    proxy = Typed(ProxyGraph)

    hug_width = 'weak'
    hug_height = 'weak'

    def child_added(self, child):
        super(FlowGraph, self).child_added(child)
        if isinstance(child, Container):
            self.request_relayout()

    @observe('edges')
    def _update(self, change):
        self.request_relayout()

    @observe('selected')
    def _selected_update(self, change):
        if self.proxy is not None:
            self.proxy.show_selected()

