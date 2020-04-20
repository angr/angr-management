import logging

from PySide2.QtGui import QPainter, QColor, QCursor
from PySide2.QtCore import Qt, QRectF
from PySide2.QtWidgets import QApplication, QGraphicsSceneMouseEvent

from angr.analyses.disassembly import Value
from .qgraph_object import QCachedGraphicsItem
from .qoperand import QOperand
from ...utils import should_display_string_label, get_string_for_display, get_comment_for_display

_l = logging.getLogger(__name__)


class QInstruction(QCachedGraphicsItem):

    GRAPH_ADDR_SPACING = 20
    GRAPH_MNEMONIC_SPACING = 10
    GRAPH_OPERAND_SPACING = 2
    GRAPH_COMMENT_STRING_SPACING = 10

    INTERSPERSE_ARGS = ', '

    LINEAR_INSTRUCTION_OFFSET = 120
    COMMENT_PREFIX = "// "

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, insn, out_branch, config, parent=None,
                 container=None):
        super().__init__(parent=parent, container=container)

        # initialization
        self.workspace = workspace
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
        self._addr_width = None
        self._mnemonic = None
        self._mnemonic_width = None
        self._operands = [ ]
        self._string = None
        self._string_width = None
        self._comment = None
        self._comment_width = None
        self._legend = None

        self._init_widgets()

    def mousePressEvent(self, event: QGraphicsSceneMouseEvent):
        if event.button() == Qt.LeftButton and QApplication.keyboardModifiers() in (Qt.NoModifier, Qt.ControlModifier):
            # toggle selection
            self.infodock.toggle_instruction_selection(
                self.addr,
                insn_pos=self.scenePos(),
                unique=QApplication.keyboardModifiers() != Qt.ControlModifier)
            event.accept()
        elif event.button() == Qt.RightButton and QApplication.keyboardModifiers() == Qt.NoModifier:
            if self.addr not in self.infodock.selected_insns:
                self.infodock.toggle_instruction_selection(self.addr, insn_pos=self.scenePos(), unique=True)
            self.disasm_view.instruction_context_menu(self.insn, QCursor.pos())
            event.accept()
        elif self.workspace.plugins.handle_click_insn(self, event):
            event.accept()
        else:
            super().mousePressEvent(event)

    @property
    def addr(self):
        return self.insn.addr

    def _calc_backcolor(self):
        # First we'll check for customizations
        color = self.workspace.plugins.color_insn(self.insn.addr, self.selected)
        if color is not None:
            return color

        if self.selected:
            return QColor(0xb8, 0xc3, 0xd6)

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
        _l.debug('refreshing')
        self.load_comment()
        for operand in self._operands:
            operand.refresh()
        self._update_size()
        self.recalculate_size()

    def get_operand(self, operand_idx):
        if operand_idx < len(self._operands):
            return self._operands[operand_idx]
        return None

    def load_comment(self):
        self._comment = get_comment_for_display(self.workspace.instance.kb, self.insn.addr)
        self._update_size()

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument

        x = 0
        y = self._config.disasm_font_ascent

        painter.setRenderHints(
            QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.disasm_font)

        # background color
        backcolor = self._calc_backcolor()
        if backcolor is not None:
            painter.setBrush(backcolor)
            painter.setPen(backcolor)
            painter.drawRect(0, 0, self.width, self.height)

        # address
        if self.disasm_view.show_address:
            painter.setPen(Qt.black)
            painter.drawText(x, y, self._addr)
            x += self._addr_width + self.GRAPH_ADDR_SPACING * self.currentDevicePixelRatioF()

        # mnemonic
        painter.setPen(QColor(0, 0, 0x80))
        painter.drawText(x, y, self._mnemonic)
        x += self._mnemonic_width

        # all commas
        for operand in self._operands[:-1]:
            endpos = operand.pos().x() + operand.width
            painter.drawText(endpos, y, self.INTERSPERSE_ARGS)

        if self._operands:
            last_operand = self._operands[-1]
            x = last_operand.pos().x() + last_operand.width

        # comment or string - comments have precedence
        if self._comment is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING * self.currentDevicePixelRatioF()
            painter.setPen(Qt.darkGreen)
            painter.drawText(x, y, self.COMMENT_PREFIX + self._comment)
        elif self._string is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING * self.currentDevicePixelRatioF()
            painter.setPen(Qt.gray)
            painter.drawText(x, y, self._string)

        # any plugin instruction rendering passes
        self.workspace.plugins.draw_insn(self, painter)

    #
    # Private methods
    #

    def _init_widgets(self):
        self._operands.clear()

        self._addr = "%08x" % self.insn.addr
        self._mnemonic = self.insn.mnemonic.render()[0]

        for i, operand in enumerate(self.insn.operands):
            is_branch_target = self.insn.type in ('branch', 'call') and i == self.insn.branch_target_operand
            is_indirect_branch = self.insn.branch_type == 'indirect'
            branch_targets = None
            if is_branch_target:
                if self.out_branch is not None:
                    branch_targets = self.out_branch.targets
                else:
                    # it does not create multiple branches. e.g., a call instruction
                    if len(operand.children) == 1 and type(operand.children[0]) is Value:
                        branch_targets = (operand.children[0].val,)
            qoperand = QOperand(self.workspace, self.func_addr, self.disasm_view, self.disasm, self.infodock,
                                self.insn, operand, i, is_branch_target, is_indirect_branch, branch_targets,
                                self._config, parent=self, container=self._container)
            self._operands.append(qoperand)

        if should_display_string_label(self.workspace.instance.cfg, self.insn.addr, self.workspace.instance.project):
            # yes we should display a string label
            self._string = get_string_for_display(self.workspace.instance.cfg, self.insn.addr,
                                                  self.workspace.instance.project)

        self.load_comment()

        self._update_size()

    def _update_size(self):

        self._addr_width = self._config.disasm_font_metrics.width(self._addr) * self.currentDevicePixelRatioF()
        self._mnemonic_width = self._config.disasm_font_metrics.width(self._mnemonic) * self.currentDevicePixelRatioF()
        if self._string is not None:
            self._string_width = self._config.disasm_font_metrics.width(self._string) * self.currentDevicePixelRatioF()
        else:
            self._string_width = 0
        if self._comment is not None:
            self._comment_width = self._config.disasm_font_metrics.width(self.COMMENT_PREFIX + self._comment) * \
                                  self.currentDevicePixelRatioF()
        else:
            self._comment_width = 0

        x = 0
        # address
        if self.disasm_view.show_address:
            x += self._addr_width + self.GRAPH_ADDR_SPACING * self.currentDevicePixelRatioF()

        # mnemonic
        x += self._mnemonic_width + self.GRAPH_MNEMONIC_SPACING * self.currentDevicePixelRatioF()
        intersperse_width = self._config.disasm_font_metrics.width(self.INTERSPERSE_ARGS) * self.currentDevicePixelRatioF()

        # operands
        if self._operands:
            for operand in self._operands[:-1]:
                operand.setPos(x, 0)
                x += operand.boundingRect().width() + intersperse_width
            last_operand = self._operands[-1]
            last_operand.setPos(x, 0)
            x += last_operand.boundingRect().width()

        # comments/string
        if self._comment is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING * self.currentDevicePixelRatioF() + self._comment_width
        elif self._string is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING * self.currentDevicePixelRatioF() + self._string_width

        self._width = x
        self._height = self._config.disasm_font_height * self.currentDevicePixelRatioF()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
