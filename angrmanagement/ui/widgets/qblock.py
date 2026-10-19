from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QMarginsF, QRectF
from PySide6.QtGui import QPainterPath, QPen

from angrmanagement.config import Conf
from angrmanagement.present.block_tree import BlockTreeNodeOptions
from angrmanagement.present.block_tree.disasm_nodes import (
    CodeNode,
    FunctionCommentNode,
    InsnNode,
    LabelNode,
    PhiVariableNode,
    VariableNode,
    build_block_nodes,
)
from angrmanagement.present.disasm_style import block_background

from .qblock_code import QBlockCode
from .qblock_label import QBlockLabel
from .qdisasm_style import qt_background
from .qfunction_comment import QFunctionCommentBanner
from .qgraph import QSaveableGraphicsView
from .qgraph_object import QCachedGraphicsItem
from .qinstruction import QInstruction
from .qphivariable import QPhiVariable
from .qvariable import QVariable

if TYPE_CHECKING:
    from PySide6.QtWidgets import QGraphicsPathItem

    from angrmanagement.data.instance import Instance


class QBlock(QCachedGraphicsItem):
    """
    A disassembly block on the scene: one item per node of the block's lines.
    """

    TOP_PADDING = 5
    BOTTOM_PADDING = 5
    LEFT_PADDING = 10
    RIGHT_PADDING = 10
    SPACING = 0
    AIL_SHOW_CONDITIONAL_JUMP_TARGETS = True
    SHADOW_OFFSET_X = 0
    SHADOW_OFFSET_Y = 0
    MODE = None

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
        self.disassembly_level = disasm_view.disassembly_level
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.addr = addr
        self.cfg_nodes = cfg_nodes
        self.out_branches = out_branches
        self.idx = idx

        self._config = Conf

        self.objects = []  # instructions and labels
        self.nodes = []  # what they show
        self._block_item: QPainterPath | None = None
        self._block_item_obj: QGraphicsPathItem | None = None
        self.addr_to_insns = {}
        self.addr_to_labels = {}
        self.qblock_annotations = {}

        self._block_code_options: BlockTreeNodeOptions = BlockTreeNodeOptions()
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

    def _qt_item_for(self, node):
        """The scene item that draws ``node``, registered in addr_to_insns / addr_to_labels as the block did."""
        if isinstance(node, InsnNode):
            insn = QInstruction(
                self.instance,
                self.func_addr,
                self.disasm_view,
                self.disasm,
                self.infodock,
                node.insn,
                node.out_branch,
                self._config,
                linear=self.MODE == "linear",
                parent=self,
                node=node,
            )
            self.addr_to_insns[node.addr] = insn
            return insn
        if isinstance(node, LabelNode):
            label = QBlockLabel(
                node.addr,
                node.text,
                self._config,
                self.disasm_view,
                self.instance,
                self.infodock,
                parent=self,
                node=node,
            )
            self.addr_to_labels[node.addr] = label
            return label
        if isinstance(node, CodeNode):
            obj = QBlockCode(
                node.addr,
                node.tree,
                self._config,
                self.instance,
                self.infodock,
                parent=self,
                selection_mode=node.selection_mode,
            )
            node.tree.parent = obj  # Reparent
            if node.kind == "ail":
                self.addr_to_insns[self.cfg_nodes[0].addr] = obj
            return obj
        if isinstance(node, PhiVariableNode):
            return QPhiVariable(self.instance, self.disasm_view, node, self._config, parent=self, node=node)
        if isinstance(node, VariableNode):
            return QVariable(
                self.instance, self.disasm_view, node.variable, self._config, self.infodock, parent=self, node=node
            )
        if isinstance(node, FunctionCommentNode):
            return QFunctionCommentBanner(self.instance, self.func_addr, self._config, parent=self, node=node)
        raise TypeError(f"no scene item for {node!r}")

    def _init_widgets(self) -> None:
        if (scene := self.scene()) is not None:
            for obj in self.objects:
                scene.removeItem(obj)

        self.objects.clear()

        #: the block's lines, which the terminal frontend draws as well
        self.nodes = build_block_nodes(
            self.instance,
            self.func_addr,
            self.disasm,
            self.infodock,
            self.cfg_nodes,
            self.out_branches,
            self._block_code_options,
        )
        for node in self.nodes:
            self.objects.append(self._qt_item_for(node))

        self.layout_widgets()

    def layout_widgets(self):
        raise NotImplementedError


class QGraphBlock(QBlock):
    """
    A block of the graph view, with its frame, shadow and background.
    """

    MINIMUM_DETAIL_LEVEL = 0.4
    AIL_SHOW_CONDITIONAL_JUMP_TARGETS = False
    SHADOW_OFFSET_X = 5
    SHADOW_OFFSET_Y = 5
    BLOCK_ANNOTATIONS_LEFT_PADDING = 2
    MODE = "graph"

    def __init__(self, *args, **kwargs):
        self.color_override = None
        super().__init__(*args, **kwargs)

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
        plugins = self.disasm_view.workspace.plugins

        def plugin_color(addr: int):
            # color_block as always, then plugins that implement only the neutral block_style
            color = plugins.color_block(addr)
            return color if color is not None else plugins.block_style(addr, neutral_only=True)

        background = block_background(self.addr, should_omit_text, self.color_override, plugin_color)
        return qt_background(background)

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
    """
    A block of the linear view: its lines one under another.
    """

    MODE = "linear"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._height = 0
        self._width = 0

    @property
    def mode(self) -> str:
        return "linear"

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

        self._height = y_offset + Conf.disasm_font_height
        self._width = max_width

    def paint(self, painter, option, widget=None) -> None:  # pylint: disable=unused-argument
        painter.setFont(self._config.disasm_font)

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    def setVisible(self, visible):
        super().setVisible(visible)
        for obj in self.objects:
            obj.setVisible(visible)
