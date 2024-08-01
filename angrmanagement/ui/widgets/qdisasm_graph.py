from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.analyses.decompiler.utils import to_ail_supergraph
from PySide6.QtCore import QEvent, QPointF, QRect, QRectF, QSize, Qt, QTimeLine
from PySide6.QtWidgets import QFrame

from angrmanagement.config import Conf
from angrmanagement.utils import get_out_branches
from angrmanagement.utils.cfg import categorize_edges
from angrmanagement.utils.graph_layouter import GraphLayouter

from .qblock import QGraphBlock
from .qdisasm_base_control import DisassemblyLevel, QDisassemblyBaseControl
from .qgraph import QZoomableDraggableGraphicsView
from .qgraph_arrow import QDisasmGraphArrow
from .qminimap import QMiniMapView

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.disassembly import InfoDock


_l = logging.getLogger(__name__)


class QViewPortMover:
    def __init__(
        self,
        disasm_graph: QDisassemblyGraph,
        x: int,
        y: int,
        target_x: int,
        target_y: int,
        interval: int = 700,
        max_frame: int = 100,
    ) -> None:
        self.disasm_graph = disasm_graph
        self.target_x = target_x
        self.target_y = target_y

        self.initial_x = x
        self.initial_y = y
        self.x_step = (self.target_x - self.initial_x) / max_frame
        self.y_step = (self.target_y - self.initial_y) / max_frame

        self._move_timeline = QTimeLine(interval)
        self._move_timeline.setFrameRange(0, max_frame)
        self._move_timeline.setUpdateInterval(10)

    def start(self) -> None:
        self._move_timeline.frameChanged.connect(self._set_pos)
        self._move_timeline.start()

    def _set_pos(self, step) -> None:
        self.disasm_graph.centerOn(self.initial_x + self.x_step * step, self.initial_y + self.y_step * step)


class QDisassemblyGraph(QDisassemblyBaseControl, QZoomableDraggableGraphicsView):
    def __init__(self, instance: Instance, disasm_view, parent=None) -> None:
        QDisassemblyBaseControl.__init__(self, instance, disasm_view, QZoomableDraggableGraphicsView)
        QZoomableDraggableGraphicsView.__init__(self, parent=parent)

        self.instance = instance

        self.disasm = None
        self.variable_manager = None

        self._function_graph = None
        self._supergraph = None
        self._viewport_mover = None

        self._edges = None
        self._arrows = []  # A list of references to QGraphArrow objects

        self.blocks = []

        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.setFrameStyle(QFrame.Shape.NoFrame)
        self.setBackgroundBrush(Conf.disasm_view_background_color)

        self._minimap = QMiniMapView(self, parent=self)
        self._minimap.setMaximumSize(200, 400)
        self._minimap.move(20, 20)
        self._minimap.setVisible(self.disasm_view.show_minimap)

    #
    # Properties
    #

    @property
    def function_graph(self):
        return self._function_graph

    @function_graph.setter
    def function_graph(self, v) -> None:
        if v is not self._function_graph:
            self._function_graph = v

            self.reload()

    @property
    def induction_variable_analysis(self):
        return self.infodock.induction_variable_analysis

    @induction_variable_analysis.setter
    def induction_variable_analysis(self, v) -> None:
        self.infodock.induction_variable_analysis = v

    #
    # Public methods
    #

    def reload(self, old_infodock: InfoDock | None = None) -> None:
        # if there is an instruction in selection, we will want to select that instruction again after reloading this
        # view.
        selected_insns = old_infodock.selected_insns.am_obj if old_infodock is not None else set()

        self._reset_scene()
        self._arrows.clear()
        self._minimap.reload_target_scene()
        self.blocks.clear()
        self._insaddr_to_block.clear()
        if self._function_graph is None:
            return

        scene = self.scene()

        if self._disassembly_level is DisassemblyLevel.AIL:
            func = self._function_graph.function
            try:
                # always check if decompiler has cached a clinic object first
                self.disasm = self.instance.kb.structured_code[(func.addr, "pseudocode")].clinic
            except (KeyError, AttributeError):
                self.disasm = self.instance.project.analyses.Clinic(func)

            self._supergraph = to_ail_supergraph(self.disasm.cc_graph)

            def nodefunc(n):
                return n

            def branchfunc(n):
                return None

            has_idx = True
        else:
            include_ir = self._disassembly_level is DisassemblyLevel.LifterIR
            self.disasm = self.instance.project.analyses.Disassembly(
                function=self._function_graph.function, include_ir=include_ir
            )
            view = self.disasm_view.workspace.view_manager.first_view_in_category("console")
            if view is not None:
                view.push_namespace(
                    {
                        "disasm": self.disasm,
                    }
                )
            self._supergraph = self._function_graph.supergraph

            def nodefunc(n):
                return n.cfg_nodes

            branchfunc = get_out_branches
            has_idx = False

        for n in self._supergraph.nodes():
            block = QGraphBlock(
                self.instance,
                self._function_graph.function.addr,
                self.disasm_view,
                self.disasm,
                self.infodock,
                n.addr,
                nodefunc(n),
                branchfunc(n),
                scene,
                idx=n.idx if has_idx else None,
            )
            if n.addr == self._function_graph.function.addr:
                self.entry_block = block
            scene.addItem(block)
            self.blocks.append(block)

            for insn_addr in block.addr_to_insns:
                self._insaddr_to_block[insn_addr] = block

        self.request_relayout()
        self._update_scene_boundary()

        # determine initial view focus point
        self._reset_view()

        # select the old instructions
        for insn_addr in selected_insns:
            self.infodock.select_instruction(insn_addr, unique=False, use_animation=False)

        self._minimap.reload_target_scene()

    def refresh(self) -> None:
        if not self.blocks:
            return

        for b in self.blocks:
            b.clear_cache()
            b.refresh()

        self.request_relayout()
        self._update_scene_boundary()

        self._minimap.reload_target_scene()
        self._minimap.setVisible(self.disasm_view.show_minimap)

    def set_extra_render_pass(self, is_extra_pass: bool) -> None:
        super().set_extra_render_pass(is_extra_pass)
        if not is_extra_pass:
            # We hide block objects in low LoD passes. Restore them now if
            # they were hidden.
            for b in self.blocks:
                b.restore_temporarily_hidden_objects()

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

    def mousePressEvent(self, event) -> None:
        btn = event.button()

        if btn == Qt.MouseButton.ForwardButton:
            self.disasm_view.jump_forward()
        elif btn == Qt.MouseButton.BackButton:
            self.disasm_view.jump_back()
        else:
            super().mousePressEvent(event)

    def changeEvent(self, event: QEvent) -> None:
        """
        Redraw on color scheme update.
        """
        if event.type() == QEvent.Type.PaletteChange:
            self.setBackgroundBrush(Conf.disasm_view_background_color)
            self.reload()

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
        for node in self._supergraph.nodes():
            block = node_map[node.addr]
            node_sizes[node] = block.width, block.height
        gl = GraphLayouter(self._supergraph, node_sizes)

        nodes = {}
        for node, coords in gl.node_coordinates.items():
            nodes[(node.addr, node.idx)] = coords

        return nodes, gl.edges

    def request_relayout(self) -> None:
        node_coords, edges = self._layout_graph()

        self._edges = edges

        categorize_edges(self.disasm, edges)

        if not node_coords:
            print("Failed to get node_coords")
            return

        # layout nodes
        for block in self.blocks:
            x, y = node_coords[(block.addr, block.idx)]
            block.setPos(x, y)

        scene = self.scene()

        # remove exiting arrows
        for arrow in self._arrows:
            scene.removeItem(arrow)
        self._arrows.clear()

        for edge in self._edges:
            arrow = QDisasmGraphArrow(edge, self.disasm_view, self.infodock)
            self._arrows.append(arrow)
            scene.addItem(arrow)
            arrow.setPos(QPointF(*edge.coordinates[0]))

    def _update_scene_boundary(self) -> None:
        scene = self.scene()
        # Leave some margins
        rect: QRectF = scene.itemsBoundingRect()
        scene.setSceneRect(QRectF(rect.x() - 200, rect.y() - 200, rect.width() + 400, rect.height() + 400))

    def show_instruction(
        self, insn_addr, insn_pos=None, centering: bool = False, use_block_pos: bool = False, use_animation: bool = True
    ) -> None:
        block: QGraphBlock = self._insaddr_to_block.get(insn_addr, None)
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
            if use_animation:
                viewport = self.viewport()
                current_pos = self.mapToScene(viewport.width() // 2, viewport.height() // 2)
                self._viewport_mover = QViewPortMover(self, current_pos.x(), current_pos.y(), x, y)
                self._viewport_mover.start()
            else:
                self.centerOn(x, y)

    def update_label(self, addr: int, is_renaming: bool = False) -> None:
        block: QGraphBlock = self._insaddr_to_block.get(addr, None)
        if block is not None:
            if is_renaming:
                # we just need to refresh the current block
                # block.refresh()  # TODO: We should be able to just refresh that single label
                block.reload()
            else:
                # life is hard... we need to reload the block, and then re-layout the entire graph because of size
                # changes
                block.reload()
                self.request_relayout()

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
