
from PySide.QtGui import QLabel, QHBoxLayout, QSizePolicy, QCursor, QPainter, QColor
from PySide.QtCore import Qt, SIGNAL

from .qgraph_object import QGraphObject
from .qoperand import QOperand
from ...utils import should_display_string_label, get_string_for_display


class QInstruction(QGraphObject):

    ADDR_SPACING = 20
    MNEMONIC_SPACING = 10
    OPERAND_SPACING = 2
    STRING_SPACING = 5

    def __init__(self, workspace, disasm_view, disasm, variable_manager, insn, out_branch, config):
        super(QInstruction, self).__init__()

        # initialization
        self.workspace = workspace
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.variable_manager = variable_manager
        self.insn = insn
        self.out_branch = out_branch
        self._config = config

        self.selected = False

        self._width = None
        self._height = None

        # all "widgets"
        self._addr = None
        self._addr_width = None
        self._mnemonic = None
        self._mnemonic_width = None
        self._operands = [ ]
        self._string = None
        self._string_width = None

        self._init_widgets()

        #self.setContextMenuPolicy(Qt.CustomContextMenu)
        #self.connect(self, SIGNAL('customContextMenuRequested(QPoint)'), self._on_context_menu)

    @property
    def width(self):
        return self._width

    @property
    def height(self):
        return self._height

    def paint(self, painter):
        """

        :param QPainter painter:
        :return:
        """

        # selection background
        if self.selected:
            painter.setPen(QColor(0xef, 0xbf, 0xba))
            painter.setBrush(QColor(0xef, 0xbf, 0xba))
            painter.drawRect(self.x, self.y, self.width, self.height + 2)

        x = self.x

        # address
        if self.disasm_view.show_address:
            painter.setPen(Qt.black)
            painter.drawText(x, self.y + self._config.disasm_font_height, self._addr)

            x += self._addr_width + self.ADDR_SPACING

        # mnemonic
        painter.setPen(QColor(0, 0, 0x80))
        painter.drawText(x, self.y + self._config.disasm_font_height, self._mnemonic)

        x += self._mnemonic_width + self.MNEMONIC_SPACING

        # operands
        for i, op in enumerate(self._operands):
            op.x = x
            op.y = self.y
            op.paint(painter)

            x += op.width

            if i != len(self._operands) - 1:
                # draw the comma
                painter.drawText(x, self.y + self._config.disasm_font_height, ",")
                x += self._config.disasm_font_width * 1

            x += self.OPERAND_SPACING

        # string
        if self._string is not None:
            x += self.STRING_SPACING
            painter.setPen(Qt.gray)
            painter.drawText(x, self.y + self._config.disasm_font_height, self._string)

    def refresh(self):
        super(QInstruction, self).refresh()

        self._update_size()

    def select(self):
        if not self.selected:
            self.toggle_select()

    def unselect(self):
        if self.selected:
            self.toggle_select()

    def toggle_select(self):
        self.selected = not self.selected

    def select_operand(self, operand_idx):

        if operand_idx < len(self._operands):
            self._operands[operand_idx].select()

    def unselect_operand(self, operand_idx):

        if operand_idx < len(self._operands):
            self._operands[operand_idx].unselect()

    #
    # Event handlers
    #

    def on_mouse_pressed(self, button, pos):
        if button == Qt.LeftButton:
            # left click

            # is it on one of the operands?
            for op in self._operands:
                if op.x <= pos.x() < op.x + op.width:
                    op.on_mouse_pressed(button, pos)
                    return

            self.disasm_view.toggle_instruction_selection(self.insn.addr)

    def on_mouse_released(self, button, pos):
        if button == Qt.RightButton:
            # right click
            # display the context menu
            self.disasm_view.instruction_context_menu(self.insn, QCursor.pos())

    def on_mouse_doubleclicked(self, button, pos):

        if button == Qt.LeftButton:
            # left double click

            # is it on one of the operands?
            for op in self._operands:
                if op.x <= pos.x() < op.x + op.width:
                    op.on_mouse_doubleclicked(button, pos)
                    return

    #
    # Private methods
    #

    def _init_widgets(self):

        self._addr = "%08x" % self.insn.addr
        self._addr_width = self._config.disasm_font_width * len(self._addr)
        self._mnemonic = self.insn.mnemonic.render()[0]
        self._mnemonic_width = self._config.disasm_font_width * len(self._mnemonic)

        for i, operand in enumerate(self.insn.operands):
            is_branch_target = self.insn.type in ('branch', 'call') and i == self.insn.branch_target_operand
            is_indirect_branch = self.insn.branch_type == 'indirect'
            branch_targets = (self.out_branch.targets if self.out_branch is not None else None) \
                if is_branch_target else None
            operand = QOperand(self.workspace, self.disasm_view, self.disasm, self.variable_manager, self.insn, operand,
                               i, is_branch_target, is_indirect_branch, branch_targets, self._config
                               )
            self._operands.append(operand)

        if should_display_string_label(self.workspace.instance.cfg, self.insn.addr):
            # yes we should display a string label
            self._string = get_string_for_display(self.workspace.instance.cfg, self.insn.addr)
            self._string_width = self._config.disasm_font_width * len(self._string)

        self._update_size()

    def _update_size(self):

        self._height = self._config.disasm_font_height
        self._width = 0

        if self.disasm_view.show_address:
            self._width += self._addr_width + self.ADDR_SPACING

        self._width += self._mnemonic_width + self.MNEMONIC_SPACING + \
                       sum([ op.width for op in self._operands ]) + \
                       (len(self._operands) - 1) * (self._config.disasm_font_width + self.OPERAND_SPACING)
        if self._string is not None:
            self._width += self.STRING_SPACING + self._string_width
