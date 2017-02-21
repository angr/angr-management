
from functools import wraps
import logging

from PySide.QtCore import QPointF, QRectF, Qt
from PySide.QtGui import QPainterPath, QPolygonF, QGraphicsPolygonItem, QBrush

from grandalf.graphs import Graph, Edge, Vertex
from grandalf.layouts import VertexViewer, SugiyamaLayout
from grandalf.routing import EdgeViewer
from grandalf.utils.geometry import getangle

from ...utils import get_out_branches
from .qblock import QBlock
from .qgraph import QBaseGraph

l = logging.getLogger('ui.widgets.qflow_graph')


def timeit(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        import time
        start = time.time()
        r = f(*args, **kwargs)
        elapsed = time.time() - start
        print "%s takes %f sec." % (f.__name__, elapsed)

        return r
    return decorator


class EdgeRouter(object):
    def __init__(self, sug, xspace, yspace):
        self._sug = sug
        self.xspace = xspace
        self.yspace = yspace

    def _make_right_angles(self, points):
        """
        Route an edge to make sure each segment either goes horizontally or vertically

        :param list points: A list of point coordinates
        :return: A list of routed edges
        :rtype: list
        """

        new_points = [ ]

        for i, p in enumerate(points):
            if i < len(points) - 1:
                next_p = points[i + 1]
                if p[0] != next_p[0] and p[1] != next_p[1]:

                    if len(points) > 2 and i == len(points) - 2:
                        new_y = next_p[1] - self.yspace / 2
                    else:
                        new_y = p[1] + self.yspace / 2

                    new_points.append(p)
                    new_points.append((p[0], new_y))
                    new_points.append((next_p[0], new_y))
                else:
                    new_points.append(p)
            else:
                new_points.append(p)

        #print points
        #print new_points

        return new_points

    def route_edges(self, edge, points):
        """
        A simple edge routing algorithm.

        :param edge:
        :param points:
        :return:
        """

        # compute new beginning and ending
        src = edge.v[0].view
        src_width, src_height, (src_x, src_y) = src.w, src.h, src.xy

        dst = edge.v[1].view
        dst_width, dst_height, (dst_x, dst_y) = dst.w, dst.h, dst.xy

        start_point = (src_x, src_y + src_height / 2)
        end_point = (dst_x, dst_y - dst_height / 2)

        points[0] = start_point
        points[-1] = end_point

        def get_index(v):
            return self._sug.grx[v].rank, self._sug.grx[v].pos

        if end_point[1] < start_point[1]:
            # back edges are not routed. we route them here
            new_points = [ start_point, (start_point[0], start_point[1] + self.yspace / 2) ]

            src_rank, src_pos = get_index(edge.v[0])
            dst_rank, dst_pos = get_index(edge.v[1])

            assert dst_rank <= src_rank

            if end_point[0] > start_point[0]:
                # the next point should be on the left side of the source block
                p = (src_x - src_width / 2 - self.xspace / 2, src_y)
            else:
                # the next point should be on the right side of the source block
                p = (src_x + src_width / 2 + self.xspace / 2, src_y)
            new_points.append(p)

            # TODO: detect intersection with existing blocks and route the edge around them
            #for rank in xrange(src_rank - 1, dst_rank, -1):
            #    p =

            # last point
            new_points += [ (p[0], end_point[1] - self.yspace / 2), (end_point[0], end_point[1] - self.yspace / 2), end_point ]

            points[:] = new_points

        # make all corners right angles
        new_points = self._make_right_angles(points)
        del points[:]
        for p in new_points:
            points.append(p)

        #print "Points", points

        edge.view.head_angle = getangle(points[-2], points[-1])


class QDisasmGraph(QBaseGraph):

    XSPACE = 40
    YSPACE = 40
    LEFT_PADDING = 200
    TOP_PADDING = 200

    def __init__(self, workspace, parent):
        super(QDisasmGraph, self).__init__(parent)

        self.workspace = workspace
        self.disassembly_view = parent
        self.disasm = None

        self.blocks = set()
        self._function_graph = None

        self.key_pressed.connect(self._on_keypressed_event)
        #self.key_released.connect(self._on_keyreleased_event)

        self.selected_insns = set()
        self._insn_addr_to_block = { }

    @property
    def function_graph(self):
        return self._function_graph

    @function_graph.setter
    def function_graph(self, v):

        if v is not self._function_graph:
            self._function_graph = v

            self.reload()

    def reload(self):

        if self.blocks:
            for b in self.blocks.copy():
                self.remove_block(b)

        self.disasm = self.workspace.instance.project.analyses.Disassembly(function=self._function_graph.function)

        self._insn_addr_to_block = { }

        supergraph = self._function_graph.supergraph
        for n in supergraph.nodes_iter():
            block = QBlock(self.workspace, self.disassembly_view, self.disasm, n.addr, n.cfg_nodes,
                           get_out_branches(n), self)
            self.add_block(block)

            for insn_addr in block.addr_to_insns.iterkeys():
                self._insn_addr_to_block[insn_addr] = block

        self.request_relayout()

    def add_block(self, block):
        self.blocks.add(block)
        self.add_child(block)

    def remove_block(self, block):
        self.remove_child(block)
        if block in self.blocks:
            self.blocks.remove(block)

    def update_label(self, label_addr, is_renaming=False):
        """


        :return:
        """

        # if it's just a renaming, we simply update the text of the label
        if is_renaming:
            if label_addr in self._insn_addr_to_block:
                block = self._insn_addr_to_block[label_addr]
                block.update_label(label_addr)

            else:
                # umm not sure what's going wrong
                l.error('Label address %#x is not found in the current function.', label_addr)

        else:
            self.reload()

    def select_instruction(self, insn_addr, unique=True):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            # the instruction does not belong to the current function
            return

        if insn_addr not in self.selected_insns:
            if unique:
                # unselect existing ones
                self.unselect_all_instructions()
                self.selected_insns = { insn_addr }
            else:
                self.selected_insns.add(insn_addr)

            block.addr_to_insns[insn_addr].select()

    def unselect_instruction(self, insn_addr):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if insn_addr in self.selected_insns:
            self.selected_insns.remove(insn_addr)

            block.addr_to_insns[insn_addr].unselect()

    def unselect_all_instructions(self):
        for insn_addr in self.selected_insns.copy():
            self.unselect_instruction(insn_addr)

    #
    # Event handlers
    #

    def _on_keypressed_event(self, key_event):

        key = key_event.key()

        if key == Qt.Key_G:
            # jump to window
            self.disassembly_view.popup_jumpto_dialog()
            return True
        elif key == Qt.Key_N:
            # rename a label
            self.disassembly_view.popup_rename_label_dialog()
            return True

        return False

    #
    # Layout
    #

    def _layout_nodes_and_edges(self, start):
        """
        Compute coordinates for all CFG nodes and edges in the view

        :param int start: The starting address
        :return: a mapping between nodes' names and their coordinates (dict), and a list of edge coordinates (list)
        :rtype: tuple
        """

        coordinates = {}
        node_map = {}

        # Create the map
        for child in self.blocks:
            node_map[child.addr] = child

        if start not in node_map:
            return { }, [ ]

        vertices = {}
        edges = [ ]
        # Create all edges
        for s, d in self.function_graph.edges:
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

            edge = Edge(src_v, dst_v)
            edge.view = EdgeViewer()
            edges.append(edge)

        # Create all vertices
        for child in self.blocks:
            addr = child.addr
            if addr not in vertices:
                vertices[addr] = Vertex(addr)

        g = Graph(vertices.values(), edges)

        # create a view for each node
        for addr, vertex in vertices.iteritems():
            node = node_map[addr]
            size = node.size()
            width, height = size.width(), size.height()
            vertex.view = VertexViewer(width, height)

        sug = SugiyamaLayout(g.C[0])
        sug.xspace = self.XSPACE
        sug.yspace = self.YSPACE
        sug.route_edge = EdgeRouter(sug, self.XSPACE, self.YSPACE).route_edges
        sug.init_all(roots=[vertices[start]])
        sug.draw()

        # extract coordinates for nodes
        for addr, vertex in vertices.iteritems():
            x, y = vertex.view.xy
            # Convert the center coordinate to left corner coordinate
            coordinates[addr] = (x - vertex.view.w / 2, y - vertex.view.h / 2)

        # extract coordinates for edges
        edge_coordinates = [ ]
        for edge in edges:
            if hasattr(edge.view, '_pts'):
                edge_coordinates.append(edge.view._pts)

        return coordinates, edge_coordinates

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

        for child in self.blocks:
            widget_proxy = self._proxy(child)
            size = child.baseSize()
            width, height = size.width(), size.height()
            widget_proxy.setGeometry(QRectF(0.0, 0.0, width, height))

        node_coords, edge_coords = self._layout_nodes_and_edges(self.function_graph.function.addr)

        if not node_coords:
            print "Failed to get node_coords"
            return

        # layout nodes
        for child in self.blocks:
            widget_proxy = self._proxy(child)
            # width, height = child._layout_manager.best_size()
            x, y = node_coords[child.addr]
            widget_proxy.setPos(x, y)

        # draw edges
        for edges in edge_coords:
            for from_, to_ in zip(edges, edges[1:]):
                painter = QPainterPath(QPointF(*from_))
                painter.lineTo(QPointF(*to_))
                p = self.scene.addPath(painter)
                self._edge_paths.append(p)

            # arrow
            end_point = edges[-1]
            arrow = [ QPointF(end_point[0] - 3, end_point[1] - 6), QPointF(end_point[0] + 3, end_point[1] - 6), QPointF(*end_point) ]
            polygon = QGraphicsPolygonItem(QPolygonF(arrow))
            polygon.setBrush(QBrush(Qt.darkRed))

            self.scene.addItem(polygon)
            self._edge_paths.append(polygon)

        rect = self.scene.itemsBoundingRect()
        # Enlarge the rect so there is enough room at right and bottom
        rect.setX(rect.x() - self.LEFT_PADDING)
        rect.setY(rect.y() - self.TOP_PADDING)
        rect.setWidth(rect.width() + 2 * self.LEFT_PADDING)
        rect.setHeight(rect.height() + 2 * self.TOP_PADDING)

        self.scene.setSceneRect(rect)
        self.viewport().update()

        if self.selected_insns:
            self.show_selected()
        else:
            self.show_instruction(self._function_graph.function.addr)

    def show_selected(self):
        if self.selected_insns:
            addr = next(iter(self.selected_insns))
            self.show_instruction(addr)

    def show_instruction(self, insn_addr):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is not None:
            pos = block.instruction_position(insn_addr)
            x, y = pos.x(), pos.y()
            self.ensureVisible(x, y, 0, 0)
