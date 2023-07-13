from typing import TYPE_CHECKING, List, Optional

from angr.analyses.disassembly import Value
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QBrush, QCursor, QPainter
from PySide6.QtWidgets import QApplication, QGraphicsSceneMouseEvent, QGraphicsSimpleTextItem

from angrmanagement.utils import get_comment_for_display, get_string_for_display, should_display_string_label

from .qgraph_object import QCachedGraphicsItem
from .qoperand import QOperand

if TYPE_CHECKING:
    import PySide6


class QInstruction(QCachedGraphicsItem):
    GRAPH_ADDR_SPACING = 20
    GRAPH_MNEMONIC_SPACING = 10
    GRAPH_OPERAND_SPACING = 2
    GRAPH_COMMENT_STRING_SPACING = 10

    INTERSPERSE_ARGS = ", "

    LINEAR_INSTRUCTION_OFFSET = 120
    COMMENT_PREFIX = "// "

    def __init__(self, instance, func_addr, disasm_view, disasm, infodock, insn, out_branch, config, parent=None):
        super().__init__(parent=parent)

        # initialization
        self.instance = instance
        self.func_addr = func_addr
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.infodock = infodock
        self.variable_manager = infodock.variable_manager
        self.insn = insn
        self.out_branch = out_branch
        self._config = config

        # all "widgets"
        self._addr = None
        self._mnemonic = None
        self._addr_item: QGraphicsSimpleTextItem = None
        self._mnemonic_item: QGraphicsSimpleTextItem = None
        self._operands: List[QOperand] = []
        self._commas: List[QGraphicsSimpleTextItem] = []
        self._string = None
        self._string_item: Optional[QGraphicsSimpleTextItem] = None
        self._comment = None
        self._comment_items: Optional[List[QGraphicsSimpleTextItem]] = None  # one comment per line
        self._legend = None
        self._width = 0
        self._height = 0

        self._init_widgets()

    def contextMenuEvent(self, event: "PySide6.QtWidgets.QGraphicsSceneContextMenuEvent") -> None:
        pass

    def mouseDoubleClickEvent(self, event: QGraphicsSceneMouseEvent):
        self.infodock.unselect_all_instructions()
        self.infodock.toggle_instruction_selection(self.addr, insn_pos=self.scenePos(), unique=True)
        self.disasm_view._insn_addr_on_context_menu = self.addr
        self.disasm_view._insn_menu.insn_addr = self.addr
        self.disasm_view.popup_patch_dialog()
        event.accept()

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent):
        if self.disasm_view.workspace.plugins.handle_click_insn(self, event):
            # stop handling this event if the event has been handled by a plugin
            event.accept()
        elif event.button() == Qt.LeftButton and QApplication.keyboardModifiers() in (
            Qt.NoModifier,
            Qt.ControlModifier,
        ):
            # toggle selection
            self.infodock.toggle_instruction_selection(
                self.addr, insn_pos=self.scenePos(), unique=QApplication.keyboardModifiers() != Qt.ControlModifier
            )
            event.accept()
        elif event.button() == Qt.RightButton and QApplication.keyboardModifiers() == Qt.NoModifier:
            if self.addr not in self.infodock.selected_insns:
                self.infodock.toggle_instruction_selection(self.addr, insn_pos=self.scenePos(), unique=True)
            self.disasm_view.instruction_context_menu(self.insn, QCursor.pos())
            event.accept()
        else:
            super().mousePressEvent(event)

    @property
    def addr(self):
        return self.insn.addr

    def _calc_backcolor(self):
        # First we'll check for customizations
        color = self.disasm_view.workspace.plugins.color_insn(self.insn.addr, self.selected, self.disasm_view)
        if color is not None:
            return color

        if self.selected:
            return self._config.disasm_view_node_instruction_selected_background_color

        if not self.instance.patches.am_none:
            patches = self.instance.patches.get_all_patches(self.insn.addr, self.insn.size)
            if len(patches):
                return Qt.darkYellow

        return None  # None here means transparent, reusing the block color

    @property
    def selected(self):
        """
        If this instruction is selected or not.

        :return:    True if it is selected, False otherwise.
        :rtype:     bool
        """

        return self.infodock.is_instruction_selected(self.addr)

    def clear_cache(self):
        super().clear_cache()
        for obj in self._operands:
            obj.clear_cache()

    def refresh(self):
        self.load_comment()
        self._init_comments_or_string()

        for operand in self._operands:
            operand.refresh()

        self._layout_items_and_update_size()
        self.recalculate_size()

    def get_operand(self, operand_idx):
        if operand_idx < len(self._operands):
            return self._operands[operand_idx]
        return None

    def load_comment(self):
        if self.instance.kb is None:
            self._comment = None
        else:
            self._comment = get_comment_for_display(self.instance.kb, self.insn.addr)

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument
        painter.setRenderHints(QPainter.Antialiasing | QPainter.SmoothPixmapTransform)

        # background color
        backcolor = self._calc_backcolor()
        if backcolor is not None:
            painter.setBrush(backcolor)
            painter.setPen(backcolor)
            painter.drawRect(0, 0, self.width, self.height)

        # any plugin instruction rendering passes
        self.disasm_view.workspace.plugins.draw_insn(self, painter)

    #
    # Private methods
    #

    def _init_widgets(self):
        self.load_comment()
        self._operands.clear()

        # address
        self._addr = "%08x" % self.insn.addr
        self._addr_item = QGraphicsSimpleTextItem(self)
        self._addr_item.setBrush(QBrush(self._config.disasm_view_node_address_color))
        self._addr_item.setFont(self._config.disasm_font)
        self._addr_item.setText(self._addr)

        # mnemonic
        self._mnemonic = self.insn.mnemonic.render()[0]
        self._mnemonic_item = QGraphicsSimpleTextItem(self)
        self._mnemonic_item.setFont(self._config.disasm_font)
        self._mnemonic_item.setBrush(self._config.disasm_view_node_mnemonic_color)
        self._mnemonic_item.setText(self._mnemonic)

        # operands
        for i, operand in enumerate(self.insn.operands):
            is_branch_target = self.insn.type in ("branch", "call") and i == self.insn.branch_target_operand
            is_indirect_branch = self.insn.branch_type == "indirect"
            branch_targets = None
            if is_branch_target:
                if self.out_branch is not None:
                    branch_targets = self.out_branch.targets
                else:
                    # it does not create multiple branches. e.g., a call instruction
                    if len(operand.children) == 1 and type(operand.children[0]) is Value:
                        branch_targets = (operand.children[0].val,)
            qoperand = QOperand(
                self.instance,
                self.func_addr,
                self.disasm_view,
                self.disasm,
                self.infodock,
                self.insn,
                operand,
                i,
                is_branch_target,
                is_indirect_branch,
                branch_targets,
                self._config,
                parent=self,
            )
            self._operands.append(qoperand)

        # all commas
        for _ in range(len(self._operands) - 1):
            comma = QGraphicsSimpleTextItem(self.INTERSPERSE_ARGS, self)
            comma.setFont(self._config.disasm_font)
            comma.setBrush(self._config.disasm_view_node_mnemonic_color)
            self._commas.append(comma)

        if should_display_string_label(self.instance.cfg, self.insn.addr, self.instance.project):
            # yes we should display a string label
            self._string = get_string_for_display(self.instance.cfg, self.insn.addr, self.instance.project)
            if self._string is None:
                self._string = "<Unknown>"

        self._init_comments_or_string()

        self._layout_items_and_update_size()

    def _init_comments_or_string(self):
        # remove existing comments or strings
        if self._comment_items:
            for comm in self._comment_items:
                comm: QGraphicsSimpleTextItem
                comm.setParentItem(None)
            self._comment_items = None
        elif self._string_item is not None:
            self._string_item.setParentItem(None)
            self._string_item = None

        # comment or string - comments have precedence
        if self._comment:
            self._string_item = None
            lines = self._comment.split("\n")
            self._comment_items = []
            for line in lines:
                comment = QGraphicsSimpleTextItem(self.COMMENT_PREFIX + line, self)
                comment.setFont(self._config.disasm_font)
                comment.setBrush(self._config.disasm_view_comment_color)
                self._comment_items.append(comment)
        elif self._string is not None:
            self._comment_items = None
            self._string_item = QGraphicsSimpleTextItem(self._string, self)
            self._string_item.setFont(self._config.disasm_font)
            self._string_item.setBrush(self._config.disasm_view_string_color)

    def _layout_items_and_update_size(self):
        x, y = 0, 0

        # address
        if self.disasm_view.show_address:
            self._addr_item.setVisible(True)
            self._addr_item.setPos(x, y)
            x += self._addr_item.boundingRect().width() + self.GRAPH_ADDR_SPACING
        else:
            self._addr_item.setVisible(False)

        # mnemonic
        self._mnemonic_item.setPos(x, y)
        x += self._mnemonic_item.boundingRect().width() + self.GRAPH_MNEMONIC_SPACING

        # operands and commas
        for operand, comma in zip(self._operands, self._commas):
            operand.setPos(x, y)
            x += operand.boundingRect().width()
            comma.setPos(x, y)
            x += comma.boundingRect().width()

        # the last operand
        if self._operands:
            self._operands[-1].setPos(x, y)
            x += self._operands[-1].boundingRect().width()

        # comments and strings
        if self._comment_items:
            x += self.GRAPH_COMMENT_STRING_SPACING
            max_comment_width = 0
            for comment in self._comment_items:
                comment.setPos(x, y)
                max_comment_width = max(comment.boundingRect().width(), max_comment_width)
                y += comment.boundingRect().height()
            x += max_comment_width
        elif self._string_item is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING
            self._string_item.setPos(x, y)
            x += self._string_item.boundingRect().width()
            y += self._string_item.boundingRect().height()
        else:
            y = self._mnemonic_item.boundingRect().height()

        # update size
        self._width = x
        self._height = y
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
