from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.disassembly import Instruction, IROp
from angr.sim_variable import SimRegisterVariable
from PySide6.QtCore import QMarginsF, QRectF
from PySide6.QtGui import QPainterPath, QPen

from angrmanagement.config import Conf
from angrmanagement.utils import get_block_objects, get_label_text, get_out_branches_for_insn
from angrmanagement.utils.block_objects import FunctionHeader, Label, PhiVariable, Variables

from .block_code_objects import QAilObj, QBlockCodeOptions, QIROpObj
from .qblock_code import QBlockCode
from .qblock_label import QBlockLabel
from .qfunction_header import QFunctionHeader
from .qgraph import QSaveableGraphicsView
from .qgraph_object import QCachedGraphicsItem
from .qinstruction import QInstruction
from .qphivariable import QPhiVariable
from .qvariable import QVariable

if TYPE_CHECKING:
    from PySide6.QtWidgets import QGraphicsPathItem

    from angrmanagement.data.instance import Instance


class QBlock(QCachedGraphicsItem):
    TOP_PADDING = 5
    BOTTOM_PADDING = 5
    LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0
    AIL_SHOW_CONDITIONAL_JUMP_TARGETS = True
    SHADOW_OFFSET_X = 0
    SHADOW_OFFSET_Y = 0

    def __init__(
        self,
        instance: Instance,
        func_addr,
        disasm_view,
        disasm,
        infodock,
        addr: int,
        cfg_nodes,
        out_branches,
        parent=None,
        idx: int | None = None,
    ) -> None:
        super().__init__(parent=parent)

        # initialization
        self.instance = instance
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.addr = addr
        self.cfg_nodes = cfg_nodes
        self.out_branches = out_branches
        self.idx = idx

        self._config = Conf

        self.objects = []  # instructions and labels
        self._block_item: QPainterPath | None = None
        self._block_item_obj: QGraphicsPathItem | None = None
        self.addr_to_insns = {}
        self.addr_to_labels = {}
        self.qblock_annotations = {}

        self._block_code_options: QBlockCodeOptions = QBlockCodeOptions()
        self._update_block_code_options()

        self._init_widgets()

        self._objects_are_hidden = False
        self._objects_are_temporarily_hidden = False

        self._create_block_item()

        self.setAcceptHoverEvents(True)

    #
    # Properties
    #

    @property
    def mode(self):
        raise NotImplementedError

    @property
    def width(self):
        return self.boundingRect().width()

    @property
    def height(self):
        return self.boundingRect().height()

    #
    # Public methods
    #

    def clear_cache(self) -> None:
        super().clear_cache()
        for obj in self.objects:
            obj.clear_cache()

    def remove_children_from_scene(self) -> None:
        """
        Remove this block and its objects from the scene. Note that it does not remove this block itself from the
        scene; you need to do it once returning from this method.
        """

        scene = self.scene()
        if scene is None:
            return

        if self._block_item_obj is not None:
            scene.removeItem(self._block_item_obj)
            self._block_item_obj = None

        for obj in self.objects:
            scene.removeItem(obj)

        self.objects.clear()
        self.addr_to_insns.clear()
        self.addr_to_labels.clear()
        self.qblock_annotations.clear()

    def _update_block_code_options(self) -> None:
        self._block_code_options.show_conditional_jump_targets = self.AIL_SHOW_CONDITIONAL_JUMP_TARGETS
        self._block_code_options.show_variables = self.disasm_view.show_variable
        self._block_code_options.show_variable_identifiers = self.disasm_view.show_variable_identifier

    def refresh(self) -> None:
        self._update_block_code_options()
        for obj in self.objects:
            obj.refresh()
        self.layout_widgets()
        self.recalculate_size()
        self._create_block_item()
        self.update()

    def reload(self) -> None:
        self._init_widgets()
        self.refresh()

    def size(self):
        return self.width, self.height

    def instruction_position(self, insn_addr):
        if insn_addr in self.addr_to_insns:
            insn = self.addr_to_insns[insn_addr]
            pos = insn.pos()
            return pos.x(), pos.y()

        return None

    #
    # Initialization
    #

    def _create_block_item(self) -> None:
        """
        Create the block background and border.
        """
        if self._block_item_obj is not None and (scene := self.scene()) is not None:
            scene.removeItem(self._block_item_obj)
            self._block_item = None
            self._block_item_obj = None

        self._block_item = QPainterPath()
        self._block_item.addRoundedRect(
            0,
            0,
            self.width - self.SHADOW_OFFSET_X,
            self.height - self.SHADOW_OFFSET_Y,
            self._config.disasm_view_node_rounding,
            self._config.disasm_view_node_rounding,
        )

    def _init_ail_block_widgets(self) -> None:
        bn = self.cfg_nodes
        if bn.addr in self.disasm.kb.labels:
            label = QBlockLabel(
                bn.addr,
                get_label_text(bn.addr, self.disasm.kb),
                self._config,
                self.disasm_view,
                self.instance,
                self.infodock,
                parent=self,
            )
            self.objects.append(label)
            self.addr_to_labels[bn.addr] = label

        # always add the block name as a label and instruction:
        block_name_label = QBlockLabel(
            bn.addr, f"loc_{hex(bn.addr)}:", self._config, self.disasm_view, self.instance, self.infodock, parent=self
        )
        self.objects.append(block_name_label)
        self.addr_to_labels[bn.addr] = block_name_label

        for stmt in bn.statements:
            code_obj = QAilObj(stmt, self.instance, self.infodock, parent=None, options=self._block_code_options)
            obj = QBlockCode(
                stmt.ins_addr, code_obj, self._config, self.disasm_view, self.instance, self.infodock, parent=self
            )
            code_obj.parent = obj  # Reparent
            self.objects.append(obj)
            self.addr_to_insns[bn.addr] = obj

    def _init_disassembly_block_widgets(self) -> None:
        for obj in get_block_objects(self.disasm, self.cfg_nodes, self.func_addr):
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(
                    self.instance,
                    self.func_addr,
                    self.disasm_view,
                    self.disasm,
                    self.infodock,
                    obj,
                    out_branch,
                    self._config,
                    parent=self,
                )
                self.objects.append(insn)
                self.addr_to_insns[obj.addr] = insn
            elif isinstance(obj, Label):
                label = QBlockLabel(
                    obj.addr, obj.text, self._config, self.disasm_view, self.instance, self.infodock, parent=self
                )
                self.objects.append(label)
                self.addr_to_labels[obj.addr] = label
            elif isinstance(obj, IROp):
                code_obj = QIROpObj(obj, self.infodock, parent=None)
                disp_obj = QBlockCode(
                    obj.addr, code_obj, self._config, self.disasm_view, self.instance, self.infodock, parent=self
                )
                code_obj.parent = disp_obj  # Reparent
                self.objects.append(disp_obj)
            elif isinstance(obj, PhiVariable):
                if not isinstance(obj.variable, SimRegisterVariable):
                    phivariable = QPhiVariable(self.instance, self.disasm_view, obj, self._config, parent=self)
                    self.objects.append(phivariable)
            elif isinstance(obj, Variables):
                for var in obj.variables:
                    variable = QVariable(self.instance, self.disasm_view, var, self._config, self.infodock, parent=self)
                    self.objects.append(variable)
            elif isinstance(obj, FunctionHeader):
                self.objects.append(
                    QFunctionHeader(
                        self.func_addr,
                        obj.name,
                        obj.prototype,
                        obj.args,
                        self._config,
                        self.disasm_view,
                        self.infodock,
                        parent=self,
                    )
                )

    def _init_widgets(self) -> None:
        if (scene := self.scene()) is not None:
            for obj in self.objects:
                scene.removeItem(obj)

        self.objects.clear()

        if isinstance(self.disasm, Clinic):
            self._init_ail_block_widgets()
        else:
            self._init_disassembly_block_widgets()

        self.layout_widgets()

    def layout_widgets(self):
        raise NotImplementedError


class QGraphBlock(QBlock):
    MINIMUM_DETAIL_LEVEL = 0.4
    AIL_SHOW_CONDITIONAL_JUMP_TARGETS = False
    SHADOW_OFFSET_X = 5
    SHADOW_OFFSET_Y = 5
    BLOCK_ANNOTATIONS_LEFT_PADDING = 2

    @property
    def mode(self) -> str:
        return "graph"

    def layout_widgets(self) -> None:
        x, y = self.LEFT_PADDING, self.TOP_PADDING

        if self.qblock_annotations and self.qblock_annotations.scene():
            self.qblock_annotations.scene().removeItem(self.qblock_annotations)

        self.qblock_annotations = self.disasm_view.fetch_qblock_annotations(self)

        for obj in self.objects:
            if self.qblock_annotations.width > 0:
                obj.setPos(self.BLOCK_ANNOTATIONS_LEFT_PADDING + self.qblock_annotations.width + x, y)
            else:
                obj.setPos(x, y)
            if isinstance(obj, QInstruction) and self.qblock_annotations.get(obj.addr):
                qinsn_annotations = self.qblock_annotations.get(obj.addr)
                for qinsn_annotation in qinsn_annotations:
                    qinsn_annotation.setY(obj.y())
            y += obj.boundingRect().height()

    def hoverEnterEvent(self, event) -> None:
        self.infodock.hover_block(self.addr)
        event.accept()

    def hoverLeaveEvent(self, event) -> None:
        self.infodock.unhover_block(self.addr)
        event.accept()

    def mousePressEvent(self, event) -> None:
        if self.disasm_view.workspace.plugins.handle_click_block(self, event):
            # stop handling this event if the event has been handled by a plugin
            event.accept()
            return

        # the block is selected
        self.on_selected()

        super().mousePressEvent(event)

    def _calc_backcolor(self, should_omit_text):
        color = self.disasm_view.workspace.plugins.color_block(self.addr)
        if color is not None:
            return color

        if should_omit_text:
            return self._config.disasm_view_node_zoomed_out_background_color

        return self._config.disasm_view_node_background_color

    def _set_block_objects_visibility(self, visible: bool) -> None:
        for obj in self.objects:
            obj.setVisible(visible)
            obj.setEnabled(visible)

    def restore_temporarily_hidden_objects(self) -> None:
        if self._objects_are_temporarily_hidden != self._objects_are_hidden:
            self._set_block_objects_visibility(not self._objects_are_hidden)
            self._objects_are_temporarily_hidden = self._objects_are_hidden

    def paint(self, painter, option, widget=None) -> None:  # pylint: disable=unused-argument
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        should_omit_text = lod < QGraphBlock.MINIMUM_DETAIL_LEVEL

        painter.setBrush(self._config.disasm_view_node_shadow_color)
        painter.setPen(self._config.disasm_view_node_shadow_color)
        assert self._block_item is not None
        shadow_path = QPainterPath(self._block_item)
        shadow_path.translate(self.SHADOW_OFFSET_X, self.SHADOW_OFFSET_Y)
        painter.drawPath(shadow_path)

        # background of the node
        painter.setBrush(self._calc_backcolor(should_omit_text))
        if self.infodock.is_block_selected(self.addr):
            painter.setPen(QPen(self._config.disasm_view_selected_node_border_color, 2.5))
        else:
            painter.setPen(QPen(self._config.disasm_view_node_border_color, 1.5))

        self._block_item_obj = painter.drawPath(self._block_item)

        # content drawing is handled by qt since children are actual child widgets

        # if we are too far zoomed out, do not draw the text
        if self._objects_are_hidden != should_omit_text:
            self._set_block_objects_visibility(not should_omit_text)
            view = self.scene().parent()
            assert isinstance(view, QSaveableGraphicsView)
            if view.is_extra_render_pass:
                self._objects_are_temporarily_hidden = should_omit_text
            else:
                self._objects_are_hidden = should_omit_text

        # extra content
        self.disasm_view.workspace.plugins.draw_block(self, painter)

    def on_selected(self) -> None:
        self.infodock.select_block(self.addr)

    def _boundingRect(self):
        cbr = self.childrenBoundingRect()
        margins = QMarginsF(
            self.LEFT_PADDING,
            self.TOP_PADDING,
            self.RIGHT_PADDING + self.SHADOW_OFFSET_X,
            self.BOTTOM_PADDING + self.SHADOW_OFFSET_Y,
        )
        return cbr.marginsAdded(margins)


class QLinearBlock(QBlock):
    ADDRESS_PADDING = 10

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._height = 0
        self._width = 0

    @property
    def mode(self) -> str:
        return "linear"

    @staticmethod
    def format_address(addr: int) -> str:
        return f"{addr:08x}"

    def layout_widgets(self) -> None:
        y_offset = 0

        max_width = 0

        for obj in self.objects:
            y_offset += self.SPACING
            obj_start = 0
            obj.setPos(obj_start, y_offset)
            if obj_start + obj.width > max_width:
                max_width = obj_start + obj.boundingRect().width()
            y_offset += obj.boundingRect().height()

        self._height = y_offset
        self._width = max_width

    def paint(self, painter, option, widget=None) -> None:  # pylint: disable=unused-argument
        painter.setFont(self._config.disasm_font)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    def setVisible(self, visible):
        super().setVisible(visible)
        for obj in self.objects:
            obj.setVisible(visible)
