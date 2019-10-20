
import logging

from PySide2.QtCore import QRect, QPointF, Qt, QSize, QEvent, QRectF

from ...utils import get_out_branches
from ...utils.graph_layouter import GraphLayouter
from ...utils.cfg import categorize_edges
from .qblock import QGraphBlock
from .qgraph_arrow import QGraphArrow
from .qgraph import QZoomableDraggableGraphicsView
from .qdisasm_base_control import QDisassemblyBaseControl

_l = logging.getLogger(__name__)


class QDisassemblyGraph(QZoomableDraggableGraphicsView, QDisassemblyBaseControl):

    def __init__(self, workspace, disasm_view, parent=None):
        super().__init__(parent=parent)
        QDisassemblyBaseControl.__init__(self, workspace, disasm_view)

        self.workspace = workspace

        self.disasm = None
        self.variable_manager = None

        self._function_graph = None

        self._edges = None
        self._arrows = [ ]  # A list of references to QGraphArrow objects

        self.blocks = [ ]
        self._insaddr_to_block = { }

        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

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
        return self.disasm_view.infodock

    @property
    def induction_variable_analysis(self):
        return self.infodock.induction_variable_analysis

    @induction_variable_analysis.setter
    def induction_variable_analysis(self, v):
        self.infodock.induction_variable_analysis = v

    #
    # Public methods
    #

    def reload(self):
        self._reset_scene()
        self._arrows.clear()
        self.disasm = self.workspace.instance.project.analyses.Disassembly(function=self._function_graph.function)
        self.workspace.view_manager.first_view_in_category('console').push_namespace({
            'disasm': self.disasm,
        })

        self.blocks.clear()
        self._insaddr_to_block.clear()

        supergraph = self._function_graph.supergraph
        for n in supergraph.nodes():
            block = QGraphBlock(self.workspace, self._function_graph.function.addr, self.disasm_view, self.disasm,
                           self.infodock, n.addr, n.cfg_nodes, get_out_branches(n))
            if n.addr == self._function_graph.function.addr:
                self.entry_block = block
            self.scene().addItem(block)
            self.blocks.append(block)

            for insn_addr in block.addr_to_insns.keys():
                self._insaddr_to_block[insn_addr] = block

        self.request_relayout()
        # Leave some margins
        scene = self.scene()
        rect = scene.itemsBoundingRect()  # type: QRectF
        scene.setSceneRect(QRectF(rect.x() - 200, rect.y() - 200, rect.width() + 400, rect.height() + 400))

        # determine initial view focus point
        self._reset_view()

        # show the graph
        self.show()

    def refresh(self):
        if not self.blocks:
            return

        for b in self.blocks:
            b.layout_widgets()
            b.refresh()

        self.request_relayout()

    #
    # Event handlers
    #

    def event(self, event):
        """
        Reimplemented to capture the Tab keypress event.
        """

        # by default, the tab key moves focus. Hijack the tab key
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.disasm_view.keyPressEvent(event)
            return True
        return super().event(event)

    def mousePressEvent(self, event):
        btn = event.button()
        if btn == Qt.ForwardButton:
            self.disasm_view.jump_forward()
        elif btn == Qt.BackButton:
            self.disasm_view.jump_back()
        else:
            super().mousePressEvent(event)

    def on_background_click(self):
        pass

    def keyPressEvent(self, event):

        key = event.key()

        if key == Qt.Key_N:
            # rename a label
            self.disasm_view.popup_rename_label_dialog()
            return
        elif key == Qt.Key_X:
            # XRef

            # get the variable
            if self.infodock.selected_operands:
                ins_addr, operand_idx = next(iter(self.infodock.selected_operands))
                block = self._insaddr_to_block.get(ins_addr, None)
                if block is not None:
                    operand = block.addr_to_insns[ins_addr].get_operand(operand_idx)
                    if operand is not None:
                        if operand.variable is not None:
                            # Display cross references to this variable
                            self.disasm_view.popup_xref_dialog(variable=operand.variable)
                        elif operand.is_constant:
                            # Display cross references to an address
                            self.disasm_view.popup_xref_dialog(dst_addr=operand.constant_value)
            return

        super().keyPressEvent(event)

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
        for node, coords in gl.node_coordinates.items():
            nodes[node.addr] = coords

        return nodes, gl.edges

    def request_relayout(self):

        node_coords, edges = self._layout_graph()

        self._edges = edges

        categorize_edges(self.disasm, edges)

        if not node_coords:
            print("Failed to get node_coords")
            return

        # layout nodes
        for block in self.blocks:
            x, y = node_coords[block.addr]
            block.setPos(x, y)

        scene = self.scene()

        # remove exiting arrows
        for arrow in self._arrows:
            scene.removeItem(arrow)
        self._arrows.clear()

        for edge in self._edges:
            arrow = QGraphArrow(edge)
            self._arrows.append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))

    def show_instruction(self, insn_addr, insn_pos=None, centering=False, use_block_pos=False):
        block = self._insaddr_to_block.get(insn_addr, None)  # type: QGraphBlock
        if block is not None:
            if use_block_pos:
                x, y = block.mapToScene(block.x(), block.y())
            else:
                pos = block.mapToScene(*block.instruction_position(insn_addr))
                x, y = pos.x(), pos.y()

            if not centering:
                # is it visible?
                viewport = self.viewport()
                visible_area = self.mapToScene(QRect(0, 0, viewport.width(), viewport.height())).boundingRect()
                topx = visible_area.x()
                topy = visible_area.y()
                if topx <= x < topx + visible_area.width() and topy <= y < topy + visible_area.height():
                    return

            # make it visible in the center
            self.centerOn(x, y)

    #
    # Private methods
    #

    def _initial_position(self):
        entry_block_rect = self.entry_block.mapRectToScene(self.entry_block.boundingRect())
        viewport_height = self.viewport().rect().height()
        min_rect = self.scene().itemsBoundingRect()
        if min_rect.height() < (viewport_height // 1.5):
            return min_rect.center()
        else:
            focus_point = (entry_block_rect.center().x(), entry_block_rect.top() + (viewport_height // 4))
            return QPointF(*focus_point)
