
from functools import wraps
import logging

from PySide.QtCore import QPointF, QRectF, Qt, QPoint, QSize
from PySide.QtGui import QPainter, QBrush, QColor, QApplication, QMouseEvent, QResizeEvent, QPen, QImage

from ...config import Conf
from ...utils import get_out_branches
from ...utils.graph_layouter import GraphLayouter
from ...utils.cfg import categorize_edges
from ...utils.edge import EdgeSort
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


class OperandHighlightMode(object):
    SAME_IDENT = 0
    SAME_TEXT = 1


class InfoDock(object):
    def __init__(self):
        self.induction_variable_analysis = None
        self.variable_manager = None

        self.highlight_mode = OperandHighlightMode.SAME_IDENT  # default highlight mode
        self.selected_operand = None

    @property
    def smart_highlighting(self):
        return self.highlight_mode == OperandHighlightMode.SAME_IDENT

    @smart_highlighting.setter
    def smart_highlighting(self, v):
        if v:
            self.highlight_mode = OperandHighlightMode.SAME_IDENT
        else:
            self.highlight_mode = OperandHighlightMode.SAME_TEXT

    def initialize(self):
        self.selected_operand = None

    def should_highlight_operand(self, operand):
        if self.selected_operand is None:
            return False

        if self.highlight_mode == OperandHighlightMode.SAME_TEXT or self.selected_operand.variable is None:
            # when there is no related variable, we highlight as long as they have the same text
            return operand.text == self.selected_operand.text
        elif self.highlight_mode == OperandHighlightMode.SAME_IDENT:
            if self.selected_operand.variable is not None and operand.variable is not None:
                return self.selected_operand.variable.ident == operand.variable.ident

        return False


class QDisasmGraph(QBaseGraph):

    XSPACE = 40
    YSPACE = 40
    LEFT_PADDING = 1000
    TOP_PADDING = 1000

    def __init__(self, workspace, parent=None):
        super(QDisasmGraph, self).__init__(workspace, parent=parent)

        self.disassembly_view = parent
        self.disasm = None
        self.variable_manager = None
        self._variable_recovery_flavor = 'fast'

        self._function_graph = None

        self._edges = None

        self.key_pressed.connect(self._on_keypressed_event)
        #self.key_released.connect(self._on_keyreleased_event)

        self.selected_insns = set()
        self.selected_operands = set()
        self._insn_addr_to_block = { }

        self._infodock = InfoDock()

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

    @property
    def infodock(self):
        return self._infodock

    @property
    def variable_recovery_flavor(self):
        return self._variable_recovery_flavor

    @variable_recovery_flavor.setter
    def variable_recovery_flavor(self, v):
        if v in ('fast', 'accurate'):
            if v != self._variable_recovery_flavor:
                self._variable_recovery_flavor = v

                # TODO: it's enough to call refresh() here if VariableManager is unique in the project
                self.reload()

    @property
    def induction_variable_analysis(self):
        return self._infodock.induction_variable_analysis

    @induction_variable_analysis.setter
    def induction_variable_analysis(self, v):
        self._infodock.induction_variable_analysis = v

    #
    # Public methods
    #

    def reload(self):
        if self.blocks:
            for b in self.blocks.copy():
                self.remove_block(b)

        # variable recovery
        if self._variable_recovery_flavor == 'fast':
            vr = self.workspace.instance.project.analyses.VariableRecoveryFast(self._function_graph.function)
        else:
            vr = self.workspace.instance.project.analyses.VariableRecovery(self._function_graph.function)
        self.variable_manager = vr.variable_manager
        self._infodock.initialize()
        self._infodock.variable_manager = vr.variable_manager
        self.disasm = self.workspace.instance.project.analyses.Disassembly(function=self._function_graph.function)

        self._insn_addr_to_block = { }

        supergraph = self._function_graph.supergraph
        for n in supergraph.nodes():
            block = QBlock(self.workspace, self._function_graph.function.addr, self.disassembly_view, self.disasm,
                           self._infodock, n.addr, n.cfg_nodes, get_out_branches(n)
                           )
            self.add_block(block)

            for insn_addr in block.addr_to_insns.iterkeys():
                self._insn_addr_to_block[insn_addr] = block

        self.request_relayout()

    def refresh(self):

        if not self.blocks:
            return

        for b in self.blocks:
            b.refresh()

        self.request_relayout(ensure_visible=False)

    def save_image_to(self, path):

        TOP_MARGIN = 50
        LEFT_MARGIN = 50

        # Determine the size of the entire graph
        graph_size = self._graph_size()

        image_size = QSize(graph_size.width() + LEFT_MARGIN * 2,
                           graph_size.height() + TOP_MARGIN * 2
                           )

        image = QImage(image_size, QImage.Format_ARGB32)
        image.fill(Qt.white)  # white background

        painter = QPainter(image)
        painter.translate(TOP_MARGIN, LEFT_MARGIN)
        painter.setRenderHint(QPainter.TextAntialiasing)
        self._paint(painter,
                    QPoint(-TOP_MARGIN, -LEFT_MARGIN),
                    QPoint(image_size.width(), image_size.height())
                    )
        painter.end()

        image.save(path)

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

        if (insn_addr, operand_idx) not in self.selected_operands:
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

        topleft_point = self._to_graph_pos(QPoint(0, 0))
        bottomright_point = self._to_graph_pos(QPoint(self.width(), self.height()))

        self._paint(painter, topleft_point, bottomright_point)

    def mousePressEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            block = self._get_block_by_pos(event.pos())
            if block is not None:
                # clicking on a block
                block.on_mouse_pressed(event.button(), self._to_graph_pos(event.pos()))
                event.accept()
                return

        super(QDisasmGraph, self).mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.RightButton:
            block = self._get_block_by_pos(event.pos())
            if block is not None:
                block.on_mouse_released(event.button(), self._to_graph_pos(event.pos()))
            event.accept()
            return

        super(QDisasmGraph, self).mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        """

        :param QMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            block = self._get_block_by_pos(event.pos())
            if block is not None:
                block.on_mouse_doubleclicked(event.button(), self._to_graph_pos(event.pos()))
            event.accept()
            return True

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
        elif key == Qt.Key_X:
            # XRef

            # get the variable
            if self.selected_operands:
                ins_addr, operand_idx = next(iter(self.selected_operands))
                block = self._insn_addr_to_block.get(ins_addr, None)
                if block is not None:
                    operand = block.addr_to_insns[ins_addr].get_operand(operand_idx)
                    if operand is not None and operand.variable is not None:
                        self.disassembly_view.popup_xref_dialog(operand.variable)
            return True
        elif key == Qt.Key_Escape or (key == Qt.Key_Left and QApplication.keyboardModifiers() & Qt.ALT != 0):
            # jump back
            self.disassembly_view.jump_back()
            return True
        elif key == Qt.Key_Right and QApplication.keyboardModifiers() & Qt.ALT != 0:
            # jump forward
            self.disassembly_view.jump_forward()

        elif key == Qt.Key_A:
            # switch between highlight mode
            self.disassembly_view.toggle_smart_highlighting(not self.infodock.smart_highlighting)

        return False

    #
    # Layout
    #

    def _graph_size(self):

        width, height = 0, 0

        for block in self.blocks:
            if block.x + block.width > width:
                width = block.x + block.width
            if block.y + block.height > height:
                height = block.y + block.height

        # TODO: Check all edges as well

        return QSize(width, height)

    def _layout_graph(self):

        node_sizes = {}
        node_map = {}
        for block in self.blocks:
            node_map[block.addr] = block
        for node in self.function_graph.supergraph.nodes():
            block = node_map[node.addr]
            node_sizes[node] = block.width, block.height
        gl = GraphLayouter(self.function_graph.supergraph, node_sizes)

        nodes = { }
        for node, coords in gl.node_coordinates.iteritems():
            nodes[node.addr] = coords

        return nodes, gl.edges

    def request_relayout(self, ensure_visible=True):

        node_coords, edges = self._layout_graph()

        self._edges = edges

        categorize_edges(self.disasm, edges)

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

        if ensure_visible:
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

    def _paint(self, painter, topleft, bottomright):

        # Set the default font
        painter.setFont(Conf.disasm_font)
        # Draw edges
        self._draw_edges(painter, topleft, bottomright)
        # Draw nodes
        self._draw_nodes(painter, topleft, bottomright)

    def _draw_nodes(self, painter, topleft_point, bottomright_point):

        # draw nodes
        for block in self.blocks:

            # safety check
            if block.x is None or block.y is None:
                l.warning("Failed to assign coordinates to block %s.", block)
                continue

            # optimization: don't paint blocks that are outside of the current range
            block_topleft_point = QPoint(block.x, block.y)
            block_bottomright_point = QPoint(block.x + block.width, block.y + block.height)
            if block_topleft_point.x() > bottomright_point.x() or block_topleft_point.y() > bottomright_point.y():
                continue
            elif block_bottomright_point.x() < topleft_point.x() or block_bottomright_point.y() < topleft_point.y():
                continue
            block.paint(painter)

    def _draw_edges(self, painter, topleft_point, bottomright_point):

        # draw edges
        if self._edges:
            for edge in self._edges:
                edge_coords = edge.coordinates

                if edge.sort == EdgeSort.BACK_EDGE:
                    # it's a back edge
                    # Honey
                    color = QColor(0xf9, 0xd5, 0x77)
                elif edge.sort == EdgeSort.TRUE_BRANCH:
                    # True branch
                    # Aqar
                    color = QColor(0x79, 0xcc, 0xcd)
                elif edge.sort == EdgeSort.FALSE_BRANCH:
                    # False branch
                    # Tomato
                    color = QColor(0xf1, 0x66, 0x64)
                else:
                    # Dark Gray
                    color = QColor(0x56, 0x5a, 0x5c)
                pen = QPen(color)
                pen.setWidth(2)
                painter.setPen(pen)

                for from_, to_ in zip(edge_coords, edge_coords[1:]):
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
                end_point = (edge_coords[-1][0], edge_coords[-1][1])
                arrow = [QPointF(end_point[0] - 3, end_point[1]), QPointF(end_point[0] + 3, end_point[1]),
                         QPointF(end_point[0], end_point[1] + 6)]
                brush = QBrush(color)
                painter.setBrush(brush)
                painter.drawPolygon(arrow)
