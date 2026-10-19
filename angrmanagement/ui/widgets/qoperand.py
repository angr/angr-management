from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtWidgets import QApplication, QGraphicsSimpleTextItem

from angrmanagement.present.block_tree.disasm_nodes import OperandNode

from .qgraph_object import QCachedGraphicsItem

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance

log = logging.getLogger(__name__)


class QOperand(QCachedGraphicsItem):
    """
    One operand of an instruction on the scene: the text items of an :class:`OperandNode`, which owns the text, the
    variable and the branch target.
    """

    BRANCH_TARGETS_SPACING = 5
    LABEL_VARIABLE_SPACING = 5
    VARIABLE_IDENT_SPACING = 5

    def __init__(
        self,
        instance: Instance,
        func_addr,
        disasm_view,
        disasm,
        infodock,
        insn,
        operand,
        operand_index,
        is_branch_target: bool,
        is_indirect_branch: bool,
        branch_targets,
        config,
        parent=None,
        node: OperandNode | None = None,
    ) -> None:
        super().__init__(parent=parent)

        self.instance = instance
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.insn = insn
        self.operand = operand
        self.operand_index = operand_index
        self.is_branch_target = is_branch_target
        self.is_indirect_branch = is_indirect_branch
        self.branch_targets = branch_targets

        self._config = config
        #: the text of the operand and what it refers to
        self.node = (
            node
            if node is not None
            else OperandNode(
                instance,
                func_addr,
                disasm,
                infodock,
                insn,
                operand,
                operand_index,
                is_branch_target,
                is_indirect_branch,
                branch_targets,
            )
        )

        # "widgets"
        self._label_item: QGraphicsSimpleTextItem | None = None
        self._variable_label_item: QGraphicsSimpleTextItem | None = None
        self._variable_ident_item: QGraphicsSimpleTextItem | None = None
        self._branch_targets_item: QGraphicsSimpleTextItem | None = None

        self._width = None
        self._height = None

        self._init_widgets()

    #
    # Properties: the node's
    #

    @property
    def text(self):
        return self.node.text

    @property
    def variable(self):
        """The variable involved."""
        return self.node.variable

    @property
    def is_constant(self):
        return self.node.is_constant

    @property
    def constant_value(self):
        return self.node.constant_value

    @property
    def is_constant_memory(self):
        return self.node.is_constant_memory

    @property
    def constant_memory_value(self):
        return self.node.constant_memory_value

    @property
    def selected(self):
        return self.node.selected

    @property
    def operand_descriptor(self):
        return self.node.operand_descriptor

    @property
    def _branch_target(self) -> int | None:
        return self.node.branch_target

    @property
    def _is_target_func(self):
        return self.node.is_target_func

    @property
    def _label(self):
        return self.node.label

    @property
    def _variable_label(self):
        return self.node.variable_label

    @property
    def _variable_ident(self):
        return self.node.variable_ident

    @property
    def _branch_targets(self):
        return self.node.branch_targets_shown

    @property
    def _branch_targets_text(self):
        return self.node.branch_targets_text

    #
    # Event handlers
    #

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            selected = self.infodock.toggle_operand_selection(
                self.insn.addr,
                self.operand_index,
                self.operand_descriptor,
                insn_pos=self.parentItem().scenePos(),
                unique=QApplication.keyboardModifiers() != Qt.KeyboardModifier.ControlModifier,
            )
            if selected:
                # select the current instruction, too
                self.infodock.select_instruction(self.insn.addr, insn_pos=QPointF(self.x(), self.y()), unique=True)
        else:
            super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.node.activate_double("left", self.disasm_view.jump_to)
        else:
            super().mouseDoubleClickEvent(event)

    #
    # Public methods
    #

    def setVisible(self, visible):
        super().setVisible(visible)
        if self._label_item is not None:
            self._label_item.setVisible(visible)
        if self._variable_label_item is not None:
            self._variable_label_item.setVisible(visible)
        if self._variable_ident_item is not None:
            self._variable_ident_item.setVisible(visible)
        if self._branch_targets_item is not None:
            self._branch_targets_item.setVisible(visible)

    def refresh(self) -> None:
        self.node.refresh()
        self._init_widgets()
        self.recalculate_size()

    def paint(self, painter, option, widget) -> None:  # pylint: disable=unused-argument
        # Background: selected, or highlighted as equal to a selected operand
        background = self.node.background_style()
        if background:
            color = getattr(self._config, background)
            painter.setPen(color)
            painter.setBrush(color)
            painter.drawRect(0, 0, self.width, self.height)

    #
    # Private methods
    #

    def _remove_item(self, item: QGraphicsSimpleTextItem | None) -> None:
        if item is not None and (scene := self.scene()) is not None:
            scene.removeItem(item)

    def _init_widgets(self) -> None:
        node = self.node

        # label
        # [rax]
        self._remove_item(self._label_item)
        self._label_item = QGraphicsSimpleTextItem(node.label, self)
        self._label_item.setFont(self._config.disasm_font)
        self._label_item.setBrush(getattr(self._config, node.label_style))

        # variable
        # {s_10}
        self._remove_item(self._variable_label_item)
        self._variable_label_item = None
        if node.variable_label:
            self._variable_label_item = QGraphicsSimpleTextItem(node.variable_label, self)
            self._variable_label_item.setFont(self._config.disasm_font)
            self._variable_label_item.setBrush(self._config.disasm_view_variable_label_color)

        # additional branch targets
        self._remove_item(self._branch_targets_item)
        self._branch_targets_item = None
        if node.branch_targets_text:
            self._branch_targets_item = QGraphicsSimpleTextItem(node.branch_targets_text, self)
            self._branch_targets_item.setFont(self._config.disasm_font)
            self._branch_targets_item.setBrush(self._config.disasm_view_branch_target_text_color)

        # variable identifier
        self._remove_item(self._variable_ident_item)
        self._variable_ident_item = None
        if node.variable is not None and self.disasm_view.show_variable_identifier:
            self._variable_ident_item = QGraphicsSimpleTextItem(node.variable_ident, self)
            self._variable_ident_item.setFont(self._config.disasm_font)
            self._variable_ident_item.setBrush(self._config.disasm_view_variable_ident_color)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self) -> None:
        x, y = 0, 0
        assert self._label_item is not None

        # label
        self._label_item.setPos(x, y)
        x += self._label_item.boundingRect().width()

        # variable
        if self._variable_label_item is not None:
            if self.disasm_view.show_variable:
                x += self.LABEL_VARIABLE_SPACING
                self._variable_label_item.setPos(x, y)
                x += self._variable_label_item.boundingRect().width()
                self._variable_label_item.show()
            else:
                self._variable_label_item.hide()

        # additional branch targets
        if self._branch_targets_item is not None:
            x += self.BRANCH_TARGETS_SPACING
            self._branch_targets_item.setPos(x, y)
            x += self._branch_targets_item.boundingRect().width()

        # variable identifier
        if self._variable_ident_item is not None:
            x += self.VARIABLE_IDENT_SPACING
            self._variable_ident_item.setPos(x, y)
            x += self._variable_ident_item.boundingRect().width()

        self._width = x
        self._height = self._label_item.boundingRect().height()
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    def _pick_variable(self, variable_and_offsets):
        return self.node.pick_variable(variable_and_offsets)

    def _variable_has_access(self, variable, ins_addr, access_type):
        return self.node.variable_has_access(variable, ins_addr, access_type)

    def _equals_for_highlighting_purposes(self, other):
        """
        :param OperandDescriptor other: The other operand to compare with.
        """
        return self.node.equals_for_highlighting_purposes(other)
