
import logging

from PySide2.QtCore import QPointF, Qt, QSize, QEvent

from ...utils import get_out_branches
from ...utils.graph_layouter import GraphLayouter
from ...utils.cfg import categorize_edges
from .qblock import QGraphBlock
from .qgraph_arrow import QGraphArrow
from .qgraph import QZoomableDraggableGraphicsView

_l = logging.getLogger(__name__)


class QDisasmGraph(QZoomableDraggableGraphicsView):

    def __init__(self, workspace, parent=None):
        super().__init__(parent=parent)

        self.workspace = workspace

        self.disassembly_view = parent
        self.disasm = None
        self.variable_manager = None

        self._function_graph = None

        self._edges = None

        self.blocks = []

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
        return self.disassembly_view.infodock

    @property
    def induction_variable_analysis(self):
        return self.infodock.induction_variable_analysis

    @induction_variable_analysis.setter
    def induction_variable_analysis(self, v):
        self.infodock.induction_variable_analysis = v

    #
    # Public methods
    #

    def redraw(self):
        self.scene().update(self.sceneRect())

    def reload(self):
        #prof = cProfile.Profile()
        #prof.enable()
        _l.debug('Reloading disassembly graph')
        self._reset_scene()
        self.disasm = self.workspace.instance.project.analyses.Disassembly(function=self._function_graph.function)
        self.workspace.view_manager.first_view_in_category('console').push_namespace({
            'disasm': self.disasm,
        })

        self.blocks.clear()

        supergraph = self._function_graph.supergraph
        for n in supergraph.nodes():
            block = QGraphBlock(self.workspace, self._function_graph.function.addr, self.disassembly_view, self.disasm,
                           self.infodock, n.addr, n.cfg_nodes, get_out_branches(n))
            if n.addr == self._function_graph.function.addr:
                self.entry_block = block
            self.scene().addItem(block)
            self.blocks.append(block)

        self.request_relayout()

        # determine initial view focus point
        self._reset_view()

        # show the graph
        self.show()
        #prof.disable()
        #prof.dump_stats('out.log')

    def refresh(self):
        if not self.blocks:
            return

        for b in self.blocks:
            b.refresh()

        self.request_relayout()

    def _initial_position(self):
        entry_block_rect = self.entry_block.mapRectToScene(self.entry_block.boundingRect())
        viewport_height = self.viewport().rect().height()
        min_rect = self.scene().itemsBoundingRect()
        if min_rect.height() < (viewport_height // 1.5):
            return min_rect.center()
        else:
            focus_point = (entry_block_rect.center().x(), entry_block_rect.top() + (viewport_height // 4))
            return QPointF(*focus_point)

    #
    # Event handlers
    #

    def event(self, event):
        """
        Reimplemented to capture the Tab keypress event.
        """

        # by default, the tab key moves focus. Hijack the tab key
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Tab:
            self.keyPressEvent(event)
            return True
        return super().event(event)


    def mousePressEvent(self, event):
        btn = event.button()
        if btn == Qt.ForwardButton:
            self.disassembly_view.jump_forward()
        elif btn == Qt.BackButton:
            self.disassembly_view.jump_back()
        else:
            super().mousePressEvent(event)

    def on_background_click(self):
        _l.debug('Clearing because of background click')
        self.workspace.instance.selected_addr = None
        self.workspace.instance.selected_operand = None

    def keyPressEvent(self, event):

        key = event.key()

        if key == Qt.Key_N:
            # rename a label
            self.disassembly_view.popup_rename_label_dialog()
            return
        elif key == Qt.Key_X:
            # XRef

            # get the variable
            if self.selected_operands:
                ins_addr, operand_idx = next(iter(self.selected_operands))
                block = self._insn_addr_to_block.get(ins_addr, None)
                if block is not None:
                    operand = block.addr_to_insns[ins_addr].get_operand(operand_idx)
                    if operand is not None:
                        if operand.variable is not None:
                            # Display cross references to this variable
                            self.disassembly_view.popup_xref_dialog(variable=operand.variable)
                        elif operand.is_constant:
                            # Display cross references to an address
                            self.disassembly_view.popup_xref_dialog(dst_addr=operand.constant_value)
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

        min_x, max_x, min_y, max_y = 0, 0, 0, 0

        # layout nodes
        for block in self.blocks:
            x, y = node_coords[block.addr]
            block.setPos(x, y)

        for edge in self._edges:
            arrow = QGraphArrow(edge)
            self.scene().addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))

    def show_instruction(self, insn_addr, centering=False, use_block_pos=False):
        pass
