
from functools import wraps
import logging

from PySide.QtCore import QPointF, QRectF, Qt, QPoint
from PySide.QtGui import QPainter, QPainterPath, QPolygonF, QGraphicsPolygonItem, QBrush, QApplication, QMouseEvent, QResizeEvent

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
    LEFT_PADDING = 1000
    TOP_PADDING = 1000

    def __init__(self, workspace, parent):
        super(QDisasmGraph, self).__init__(parent)

        self.workspace = workspace
        self.disassembly_view = parent
        self.disasm = None

        self.blocks = set()
        self._function_graph = None

        self._edge_coords = None

        # scrolling
        self._is_scrolling = False
        self._scrolling_start = None

        self.key_pressed.connect(self._on_keypressed_event)
        #self.key_released.connect(self._on_keyreleased_event)

        self.selected_insns = set()
        self.selected_operands = set()
        self._insn_addr_to_block = { }

    #
    # Properties
    #

    @property
    def function_graph(self):
        return self._function_graph

    @function_graph.setter
    def function_graph(self, v):

        if v is not self._function_graph:
            self._function_graph = v

            self.reload()

    #
    # Public methods
    #

    def reload(self):
        if self.blocks:
            for b in self.blocks.copy():
                self.remove_block(b)

        self.disasm = self.workspace.instance.project.analyses.Disassembly(function=self._function_graph.function)

        self._insn_addr_to_block = { }

        supergraph = self._function_graph.supergraph
        for n in supergraph.nodes_iter():
            block = QBlock(self.workspace, self.disassembly_view, self.disasm, n.addr, n.cfg_nodes,
                           get_out_branches(n)
                           )
            self.add_block(block)

            for insn_addr in block.addr_to_insns.iterkeys():
                self._insn_addr_to_block[insn_addr] = block

        self.request_relayout()

    def add_block(self, block):
        self.blocks.add(block)

    def remove_block(self, block):
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

        self.viewport().update()

    def unselect_instruction(self, insn_addr):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if insn_addr in self.selected_insns:
            self.selected_insns.remove(insn_addr)

            block.addr_to_insns[insn_addr].unselect()

        self.viewport().update()

    def unselect_all_instructions(self):
        for insn_addr in self.selected_insns.copy():
            self.unselect_instruction(insn_addr)

    def select_operand(self, insn_addr, operand_idx, unique=True):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            # the instruction does not belong to the current function
            return

        if insn_addr not in self.selected_insns:
            if unique:
                # unselect existing ones
                self.unselect_all_operands()
                self.selected_operands = { (insn_addr, operand_idx) }
            else:
                self.selected_operands.add((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].select_operand(operand_idx)

        self.viewport().update()

    def unselect_operand(self, insn_addr, operand_idx):
        block = self._insn_addr_to_block.get(insn_addr, None)
        if block is None:
            return

        if (insn_addr, operand_idx) in self.selected_operands:
            self.selected_operands.remove((insn_addr, operand_idx))

            block.addr_to_insns[insn_addr].unselect_operand(operand_idx)

        self.viewport().update()

    def unselect_all_operands(self):
        for insn_addr, operand_idx in self.selected_operands.copy():
            self.unselect_operand(insn_addr, operand_idx)

    def get_block_by_pos(self, pos):
        pos = self._to_graph_pos(pos)
        x, y = pos.x(), pos.y()
        for b in self.blocks:
            if b.x <= x < b.x + b.width and b.y <= y < b.y + b.height:
                return b

        return None

    #
    # Event handlers
    #

    def resizeEvent(self, event):
        """

        :param QResizeEvent event:
        :return:
        """

        self._update_size()

    def paintEvent(self, event):
        """
        Paint the graph.

        :param event:
        :return:
        """

        painter = QPainter(self.viewport())

        # scrollbar values
        current_x = self.horizontalScrollBar().value()
        current_y = self.verticalScrollBar().value()
        # coord translation
        # (0, 0) -> middle of the page
        painter.translate(self.width() / 2 - current_x, self.height() / 2 - current_y)

        painter.setFont(self.workspace.disasm_font)

        topleft_point = self._to_graph_pos(QPoint(0, 0))
        bottomright_point = self._to_graph_pos(QPoint(self.width(), self.height()))

        # draw nodes
        for block in self.blocks:
            # optimization: don't paint blocks that are outside of the current range
            block_topleft_point = QPoint(block.x, block.y)
            block_bottomright_point = QPoint(block.x + block.width, block.y + block.height)
            if block_topleft_point.x() > bottomright_point.x() or block_topleft_point.y() > bottomright_point.y():
                continue
            elif block_bottomright_point.x() < topleft_point.x() or block_bottomright_point.y() < topleft_point.y():
                continue
            block.paint(painter)

        painter.setPen(Qt.black)

        # draw edges
        if self._edge_coords:
            for edges in self._edge_coords:
                for from_, to_ in zip(edges, edges[1:]):
                    start_point = QPointF(*from_)
                    end_point = QPointF(*to_)
                    # optimization: don't draw edges that are outside of the current scope
                    if (start_point.x() > bottomright_point.x() or start_point.y() > bottomright_point.y()) and \
                            (end_point.x() > bottomright_point.x() or end_point.y() > bottomright_point.y()):
                        continue
                    elif (start_point.x() < topleft_point.x() or start_point.y() < topleft_point.y()) and \
                            (end_point.x() < topleft_point.x() or end_point.y() < topleft_point.y()):
                        continue
                    painter.drawPolyline((start_point, end_point))

                # arrow
                # end_point = self.mapToScene(*edges[-1])
                end_point = (edges[-1][0], edges[-1][1])
                arrow = [QPointF(end_point[0] - 3, end_point[1] - 6), QPointF(end_point[0] + 3, end_point[1] - 6),
                         QPointF(end_point[0], end_point[1])]
                painter.drawPolygon(arrow)

    def mousePressEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            block = self.get_block_by_pos(event.pos())
            if block is not None:
                # clicking on a block
                block.on_mouse_pressed(event.button(), self._to_graph_pos(event.pos()))
                return

            else:
                # dragging the entire graph
                self._is_scrolling = True
                self._scrolling_start = (event.x(), event.y())
                self.viewport().grabMouse()
                return

    def mouseMoveEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if self._is_scrolling:
            pos = event.pos()
            delta = (pos.x() - self._scrolling_start[0], pos.y() - self._scrolling_start[1])
            self._scrolling_start = (pos.x(), pos.y())

            # move the graph
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - delta[0])
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - delta[1])

    def mouseReleaseEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton and self._is_scrolling:
            self._is_scrolling = False
            self.viewport().releaseMouse()

        elif event.button() == Qt.RightButton:
            block = self.get_block_by_pos(event.pos())
            if block is not None:
                block.on_mouse_released(event.button(), self._to_graph_pos(event.pos()))

    def mouseDoubleClickEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            block = self.get_block_by_pos(event.pos())
            if block is not None:
                block.on_mouse_doubleclicked(event.button(), self._to_graph_pos(event.pos()))

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
        elif key == Qt.Key_Escape or (key == Qt.Key_Left and QApplication.keyboardModifiers() & Qt.ALT != 0):
            # jump back
            self.disassembly_view.jump_back()
            return True
        elif key == Qt.Key_Right and QApplication.keyboardModifiers() & Qt.ALT != 0:
            # jump forward
            self.disassembly_view.jump_forward()

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
            width, height = size
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
                points = [ ]
                prev_0 = None
                prev_1 = None
                for p in edge.view._pts:
                    if prev_1 is not None:
                        # check if prev_1, prev_0, and p are on the same line
                        if (prev_1[0] == prev_0[0] and prev_0[0] == p[0]) or (prev_1[1] == prev_0[1] and prev_0[1] == p[1]):
                            # skip the mid point (prev_0)
                            prev_0 = p
                            continue
                        else:
                            # push the earliest point
                            points.append(prev_1)
                            prev_1 = None

                    # move forward
                    prev_1 = prev_0
                    prev_0 = p

                points.append(prev_1)
                points.append(prev_0)  # the last two points
                edge_coordinates.append(points)

        return coordinates, edge_coordinates

    def request_relayout(self):

        node_coords, edge_coords = self._layout_nodes_and_edges(self.function_graph.function.addr)

        self._edge_coords = edge_coords

        if not node_coords:
            print "Failed to get node_coords"
            return

        min_x, max_x, min_y, max_y = 0, 0, 0, 0

        # layout nodes
        for block in self.blocks:
            x, y = node_coords[block.addr]
            block.x, block.y = x, y

            min_x = min(min_x, block.x)
            max_x = max(max_x, block.x + block.width)
            min_y = min(min_y, block.y)
            max_y = max(max_y, block.y + block.height)

            # self._set_pos(widget_proxy, self.mapToScene(x, y))

        min_x -= self.LEFT_PADDING
        max_x += self.LEFT_PADDING
        min_y -= self.TOP_PADDING
        max_y += self.TOP_PADDING
        width = (max_x - min_x) + 2 * self.LEFT_PADDING
        height = (max_y - min_y) + 2 * self.TOP_PADDING

        self._update_size()

        # scrollbars
        self.horizontalScrollBar().setRange(min_x, max_x)
        self.verticalScrollBar().setRange(min_y, max_y)

        self.setSceneRect(QRectF(min_x, min_y, width, height))

        self.viewport().update()

        self._update_size()

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
            pos = QPoint(*block.instruction_position(insn_addr))
            pos_ = self._from_graph_pos(pos)

            # is it visible?
            if 0 <= pos_.x() < self.width() and 0 <= pos_.y() < self.height():
                return

            # make it visible
            x, y = pos.x(), pos.y()
            self.horizontalScrollBar().setValue(x - 50)
            self.verticalScrollBar().setValue(y - 50)

    #
    # Private methods
    #

    def _update_size(self):

        # update scrollbars
        self.horizontalScrollBar().setPageStep(self.width())
        self.verticalScrollBar().setPageStep(self.height())

    def _to_graph_pos(self, pos):
        x_offset = self.width() / 2 - self.horizontalScrollBar().value()
        y_offset = self.height() / 2 - self.verticalScrollBar().value()
        return QPoint(pos.x() - x_offset, pos.y() - y_offset)

    def _from_graph_pos(self, pos):
        x_offset = self.width() / 2 - self.horizontalScrollBar().value()
        y_offset = self.height() / 2 - self.verticalScrollBar().value()
        return QPoint(pos.x() + x_offset, pos.y() + y_offset)
