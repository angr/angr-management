
import logging

from PySide.QtGui import QLabel, QHBoxLayout, QPainter, QColor
from PySide.QtCore import Qt

from .qgraph_object import QGraphObject

l = logging.getLogger('ui.widgets.qoperand')


class QOperandBranchTarget(QLabel):
    def __init__(self, disasm_view, text, target, is_target_func, parent):

        super(QOperandBranchTarget, self).__init__(parent)

        self.setText(text)

        if is_target_func:
            self.setProperty('class', 'operand_branch_target_func')
        else:
            self.setProperty('class', 'operand_branch_target')

        self._target = target
        self._disasm_view = disasm_view

    def mouseDoubleClickEvent(self, mouse_event):
        if self._target is not None:
            self._disasm_view.jump_to(self._target)


class QOperand(QGraphObject):
    def __init__(self, workspace, disasm_view, disasm, insn, operand, operand_index, is_branch_target, is_indirect_branch,
                 branch_targets, config):
        super(QOperand, self).__init__()

        self.workspace = workspace
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.insn = insn
        self.operand = operand
        self.operand_index = operand_index
        self.is_branch_target = is_branch_target
        self.is_indirect_branch = is_indirect_branch
        self.branch_targets = branch_targets

        self._config = config

        self.selected = False

        # "widets"
        self._label = None
        self._label_width = None
        self._branch_target = None
        self._is_target_func = None

        self._init_widgets()

    #
    # Public methods
    #

    def paint(self, painter):
        """

        :param QPainter painter:
        :return:
        """

        if self.selected:
            painter.setPen(QColor(0xc0, 0xbf, 0x40))
            painter.setBrush(QColor(0xc0, 0xbf, 0x40))
            painter.drawRect(self.x, self.y, self.width, self.height + 2)

        x = self.x
        painter.setPen(QColor(0, 0, 0x80))
        painter.drawText(x, self.y + self._config.disasm_font_height, self._label)

        x += self._label_width

    def select(self):
        if not self.selected:
            self.toggle_select()

    def unselect(self):
        if self.selected:
            self.toggle_select()

    def toggle_select(self):
        self.selected = not self.selected

    #
    # Event handlers
    #

    def on_mouse_pressed(self, button, pos):
        if button == Qt.LeftButton:
            self.disasm_view.toggle_operand_selection(self.insn.addr, self.operand_index)

    def on_mouse_doubleclicked(self, button, pos):
        if button == Qt.LeftButton:
            if self._branch_target is not None:
                self.disasm_view.jump_to(self._branch_target)

    #
    # Private methods
    #

    def _branch_target_for_operand(self, operand, branch_targets):
        if not branch_targets:
            return None

        if len(branch_targets) == 1:
            return next(iter(branch_targets))

        # there are more than one targets
        # we pick the one that complies with the operand's text
        # my solution is pretty hackish...

        if operand.cs_operand.type == 2:
            imm = operand.cs_operand.imm
            if imm in branch_targets:
                # problem solved
                return imm
            else:
                # umm why?
                pass

        # try to render it
        rendered = operand.render()[0]
        for t in branch_targets:
            if "%x" % t == rendered or "%#x" == rendered:
                return t
            if t == rendered:
                return t

        # ouch not sure what to do
        l.warning('Cannot determine branch targets for operand "%s". Please report on GitHub.', rendered)
        # return a random one
        return next(iter(branch_targets))

    def _init_widgets(self):

        layout = QHBoxLayout()

        if self.is_branch_target:
            # a branch instruction
            if self.is_indirect_branch:
                # indirect jump
                self._label = self.operand.render()[0]
                self._label_width = len(self._label) * self._config.disasm_font_width

            else:
                if self.branch_targets is not None and next(iter(self.branch_targets)) in self.disasm.kb.functions:
                    # jumping to a function
                    is_target_func = True
                else:
                    # jumping to a non-function address
                    is_target_func = False

                self._label = self.operand.render()[0]
                self._label_width = len(self._label) * self._config.disasm_font_width
                self._branch_target = self._branch_target_for_operand(self.operand, self.branch_targets)
                self._is_target_func = is_target_func

        else:
            # not a branch
            self._label = self.operand.render()[0]
            self._label_width = len(self._label) * self._config.disasm_font_width

        self._update_size()

    def _update_size(self):
        self._width = self._label_width
        self._height = self._config.disasm_font_height
