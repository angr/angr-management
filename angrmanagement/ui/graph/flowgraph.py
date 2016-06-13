
from collections import defaultdict

import networkx
from grandalf.graphs import Graph, Edge, Vertex
from grandalf.layouts import VertexViewer, SugiyamaLayout

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

        if start not in node_map:
            return { }

        vertices = {}
        edges = [ ]
        # Create all edges
        for s, d in self.declaration.edges:
            src, dst = int(s), int(d)
            if src in vertices:
                src_v = vertices[src]
            else:
                src_v = Vertex(src)
                vertices[src] = src_v

            if dst in vertices:
                dst_v = vertices[dst]
            else:
                dst_v = Vertex(dst)
                vertices[dst] = dst_v

            edges.append(Edge(src_v, dst_v))

        # Create all vertices
        for child in self.children():
            addr = child.declaration.addr
            if addr not in vertices:
                vertices[addr] = Vertex(addr)

        g = Graph(vertices.values(), edges)

        # create a view for each node
        for addr, vertex in vertices.iteritems():
            node = node_map[addr]
            width, height = node._layout_manager.best_size()
            vertex.view = VertexViewer(width, height)

        sug = SugiyamaLayout(g.C[0])
        sug.init_all(roots=[vertices[start]])
        sug.draw()

        # extract coordinates
        for addr, vertex in vertices.iteritems():
            x, y = vertex.view.xy
            # Convert the center coordinate to left corner coordinate
            coordinates[addr] = (x - vertex.view.w / 2, y - vertex.view.h / 2)

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

        if not coordinates:
            return

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

