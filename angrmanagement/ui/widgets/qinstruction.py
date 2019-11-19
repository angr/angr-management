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
    GRAPH_TRACE_LEGEND_WIDTH = 30
    GRAPH_TRACE_LEGEND_SPACING = 20

    INTERSPERSE_ARGS = ', '

    LINEAR_INSTRUCTION_OFFSET = 120
    COMMENT_PREFIX = "// "

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, insn, out_branch, config, parent=None):
        super().__init__(parent=parent)

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

    def update_if_at_addr(self, old_addr, new_addr):
        if not shiboken.isValid(self):
            return True
        if old_addr == self.addr or new_addr == self.addr:
            self.update()

    def mousePressEvent(self, event):
        """

        :param QGraphicsSceneMouseEvent event:
        :return:
        """

        if event.button() == Qt.LeftButton:
            # toggle selection
            self.infodock.toggle_instruction_selection(self.addr,
                                                       insn_pos=self.scenePos(),
                                                       unique=QApplication.keyboardModifiers() != Qt.ControlModifier)
            event.accept()
        elif event.button() == Qt.RightButton:
            if QCachedGraphicsItem.ctrl_held:
                # continue on for trace load
                super().mousePressEvent(event)
            else:
                # display the context menu
                self.disasm_view.instruction_context_menu(self.insn, QCursor.pos())
        else:
            super().mousePressEvent(event)

    @property
    def addr(self):
        return self.insn.addr

    @property
    def insn_backcolor(self):
        r, g, b = None, None, None

        # First we'll check for customizations
        if self.disasm_view.insn_backcolor_callback:
            r, g, b = self.disasm_view.insn_backcolor_callback(addr=self.insn.addr, selected=self.selected)

        # Fallback to defaults if we get Nones from the callback
        if r is None or g is None or b is None:
            if self.selected:
                r, g, b = 0xef, 0xbf, 0xba

        return QColor(r, g, b) if r is not None else None

    @property
    def selected(self):
        """
        If this instruction is selected or not.

        :return:    True if it is selected, False otherwise.
        :rtype:     bool
        """

        return self.infodock.is_instruction_selected(self.addr)

    def refresh(self):
        _l.debug('refreshing')
        self.load_comment()
        for operand in self._operands:
            operand.refresh()
        self.update_trace()
        self._update_size()
        self.recalculate_size()

    def get_operand(self, operand_idx):
        if operand_idx < len(self._operands):
            return self._operands[operand_idx]
        return None

    def load_comment(self):
        self._comment = get_comment_for_display(self.workspace.instance.cfg.kb, self.insn.addr)
        if self._comment is not None:
            self._comment_width = self._config.disasm_font_width * len(self.COMMENT_PREFIX + self._comment)

    def update_trace(self):
        _l.debug('updating trace')
        if self.workspace.instance.trace is not None:
            trace = self.workspace.instance.trace
            # count is cached in trace.
            count = trace.get_count(self.insn.addr)
            _l.debug('counting trace')

            if count > 0:
                if count > self.GRAPH_TRACE_LEGEND_WIDTH:
                    jump = count / self.GRAPH_TRACE_LEGEND_WIDTH
                    self._legend = [(int(jump * i), 1) for i in
                               range(self.GRAPH_TRACE_LEGEND_WIDTH)]
                else:
                    width = self.GRAPH_TRACE_LEGEND_WIDTH // count
                    remainder = self.GRAPH_TRACE_LEGEND_WIDTH % count
                    self._legend = [(i, width + 1) for i in range(remainder)] + \
                              [(i, width) for i in range(remainder, count)]
        else:
            self._legend = None

    def paint(self, painter, option, widget):  # pylint: disable=unused-argument

        x = 0
        y = self._config.disasm_font_ascent

        painter.setRenderHints(
            QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.disasm_font)

        # selection
        backcolor = self.insn_backcolor
        if backcolor is not None:
            painter.setBrush(backcolor)
            painter.setPen(backcolor)
            painter.drawRect(0, 0, self.width, self.height)

        # address
        if self.disasm_view.show_address:
            painter.setPen(Qt.black)
            painter.drawText(x, y, self._addr)
            x += self._addr_width + self.GRAPH_ADDR_SPACING

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
            x += self.GRAPH_COMMENT_STRING_SPACING
            painter.setPen(Qt.darkGreen)
            painter.drawText(x, y, self.COMMENT_PREFIX + self._comment)
        elif self._string is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING
            painter.setPen(Qt.gray)
            painter.drawText(x, y, self._string)

        _l.debug('drawing legend')
        # legend
        self.update_trace()
        if self._legend is not None:
            _l.debug('legend is not None')
            legend_x = 0 - self.GRAPH_TRACE_LEGEND_WIDTH - self.GRAPH_TRACE_LEGEND_SPACING
            for (i, w) in self._legend:
                color = self.workspace.instance.trace.get_mark_color(self.insn.addr, i)
                painter.setPen(color)
                painter.setBrush(color)
                painter.drawRect(legend_x, 0, w, self.height)
                legend_x += w

    #
    # Private methods
    #

    def _init_widgets(self):
        self._operands.clear()

        self._addr = "%08x" % self.insn.addr
        self._addr_width = self._config.disasm_font_width * len(self._addr)
        self._mnemonic = self.insn.mnemonic.render()[0]
        self._mnemonic_width = self._config.disasm_font_width * len(self._mnemonic)

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
                                self._config, parent=self)
            self._operands.append(qoperand)

        if should_display_string_label(self.workspace.instance.cfg, self.insn.addr):
            # yes we should display a string label
            self._string = get_string_for_display(self.workspace.instance.cfg, self.insn.addr)
            self._string_width = self._config.disasm_font_width * len(self._string)

        self.load_comment()

        self._update_size()

    def _update_size(self):

        x = 0
        # address
        if self.disasm_view.show_address:
            x += self._addr_width + self.GRAPH_ADDR_SPACING

        # mnemonic
        x += self._mnemonic_width + self.GRAPH_MNEMONIC_SPACING
        intersperse_width = self._config.disasm_font_metrics.width(self.INTERSPERSE_ARGS)

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
            x += self.GRAPH_COMMENT_STRING_SPACING + self._comment_width
        elif self._string is not None:
            x += self.GRAPH_COMMENT_STRING_SPACING + self._string_width

        self._width = x
        self._height = self._config.disasm_font_height

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)
