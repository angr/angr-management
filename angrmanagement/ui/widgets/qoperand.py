import logging

from PySide2.QtWidgets import QLabel, QHBoxLayout
from PySide2.QtGui import QPainter, QColor
from PySide2.QtCore import Qt

from angr.analyses.code_location import CodeLocation
from angr.analyses.disassembly import ConstantOperand, RegisterOperand, MemoryOperand

from .qgraph_object import QGraphObject

l = logging.getLogger('ui.widgets.qoperand')


class QOperand(QGraphObject):

    BRANCH_TARGETS_SPACING = 5
    VARIABLE_IDENT_SPACING = 5

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, insn, operand, operand_index,
                 is_branch_target, is_indirect_branch, branch_targets, config):
        super(QOperand, self).__init__()

        self.workspace = workspace
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

        # the variable involved
        self.variable = None

        self._config = config

        self.selected = False

        # "widgets"
        self._label = None
        self._label_width = None
        self._variable_ident = None
        self._variable_ident_width = None
        self._branch_target = None
        self._branch_targets = None
        self._branch_targets_text = None
        self._branch_targets_text_width = None
        self._is_target_func = None

        self._init_widgets()

    #
    # Properties
    #

    @property
    def text(self):
        return self._label

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
            painter.drawRect(self.x, self.y, self.width, self.height)
        else:
            # should we highlight ourselves?
            if self.infodock.should_highlight_operand(self):
                painter.setPen(QColor(0x7f, 0xf5, 0))
                painter.setBrush(QColor(0x7f, 0xf5, 0))
                painter.drawRect(self.x, self.y, self.width, self.height)

        x = self.x

        if self._branch_target or self._branch_targets:
            if self._is_target_func:
                painter.setPen(Qt.blue)
            else:
                painter.setPen(Qt.red)
        else:
            if self.variable is not None:
                # it has a variable
                fallback = True
                if self.infodock.induction_variable_analysis is not None:
                    r = self.infodock.induction_variable_analysis.variables.get(self.variable.ident, None)
                    if r is not None and r.expr.__class__.__name__ == "InductionExpr":
                        painter.setPen(Qt.darkYellow)
                        fallback = False

                if fallback:
                    painter.setPen(QColor(0xff, 0x14, 0x93))
            else:
                painter.setPen(QColor(0, 0, 0x80))
        painter.drawText(x, self.y + self._config.disasm_font_ascent, self._label)

        x += self._label_width

        # draw additional branch targets
        if self._branch_targets_text:
            painter.setPen(Qt.darkYellow)
            x += self.BRANCH_TARGETS_SPACING
            painter.drawText(x, self.y + self._config.disasm_font_ascent, self._branch_targets_text, )
            x += self._branch_targets_text_width

        if self.variable is not None and self.disasm_view.show_variable_identifier:
            x += self.VARIABLE_IDENT_SPACING
            painter.setPen(Qt.darkGreen)
            painter.drawText(x, self.y + self._config.disasm_font_ascent, self._variable_ident)
            x += self._variable_ident_width

        # restores the color
        painter.setPen(QColor(0, 0, 0x80))

    def refresh(self):
        super(QOperand, self).refresh()

        # if self.infodock.induction_variable_analysis is not None:
        self._init_widgets()

        self._update_size()

    def select(self):
        if not self.selected:
            self.toggle_select()

    def unselect(self):
        if self.selected:
            self.toggle_select()

    def toggle_select(self):
        self.selected = not self.selected
        if self.selected:
            self.infodock.selected_operand = self
        else:
            self.infodock.selected_operand = None

    #
    # Event handlers
    #

    def on_mouse_pressed(self, button, pos):
        if button == Qt.LeftButton:
            self.disasm_view.toggle_operand_selection(self.insn.addr, self.operand_index)

    def on_mouse_doubleclicked(self, button, pos):
        if button == Qt.LeftButton:
            if self._branch_target is not None:
                self.disasm_view.jump_to(self._branch_target, src_ins_addr=self.insn.addr)

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

        if isinstance(operand, ConstantOperand):
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

    def _first_n_branch_targets(self, branch_targets, n):

        if not branch_targets:
            return [ ]

        return list(branch_targets)[ : n]

    def _init_widgets(self):

        if self.is_branch_target:
            # a branch instruction

            if self.branch_targets is not None and next(iter(self.branch_targets)) in self.disasm.kb.functions:
                # jumping to a function
                is_target_func = True
            else:
                # jumping to a non-function address
                is_target_func = False

            if self.is_indirect_branch:
                # indirect jump
                self._label = self.operand.render()[0]
                self._label_width = len(self._label) * self._config.disasm_font_width
                self._is_target_func = is_target_func

                self._branch_targets = self.branch_targets
                first_n_targets = self._first_n_branch_targets(self._branch_targets, 3)
                if first_n_targets:
                    self._branch_targets_text = "[ %s ]" % ", ".join([ "%xh" % t for t in first_n_targets ])
                    self._branch_targets_text_width = len(self._branch_targets_text) * self._config.disasm_font_width

                if self._branch_targets and len(self._branch_targets) == 1:
                    self._branch_target = next(iter(self._branch_targets))

            else:
                self._label = self.operand.render()[0]
                self._label_width = len(self._label) * self._config.disasm_font_width
                self._is_target_func = is_target_func

                self._branch_target = self._branch_target_for_operand(self.operand, self.branch_targets)

        else:
            # not a branch

            formatting = {}
            if isinstance(self.operand, MemoryOperand):
                variable_sort = 'memory'
            elif isinstance(self.operand, RegisterOperand):
                variable_sort = 'register'
            else:
                variable_sort = None

            if self.disasm_view.show_variable and variable_sort:
                # try find the corresponding variable
                variable_and_offsets = self.variable_manager[self.func_addr].find_variables_by_insn(self.insn.addr,
                                                                                                    variable_sort
                                                                                                    )
                if variable_and_offsets:
                    variable, offset = self._pick_variable(variable_and_offsets)

                    if variable is not None:
                        self.variable = variable
                        self._variable_ident = "<%s>" % variable.ident

                        if self.disasm_view.show_variable:
                            variable_str = variable.name

                            ident = (self.insn.addr, 'operand', self.operand_index)
                            if 'custom_values_str' not in formatting: formatting['custom_values_str'] = { }
                            if variable_sort == 'memory':
                                if offset == 0: custom_value_str = variable_str
                                else: custom_value_str = "%s[%d]" % (variable_str, offset)
                            else:
                                custom_value_str = ''

                            ##
                            # Hacks
                            ##
                            if self.infodock.induction_variable_analysis is not None:
                                r = self.infodock.induction_variable_analysis.variables.get(variable.ident, None)
                                if r is not None and r.expr.__class__.__name__ == "InductionExpr":
                                    custom_value_str = "i*%d+%d" % (r.expr.stride, r.expr.init)
                                if r is not None and r.expr.__class__.__name__ == "Add" and r.expr.operands[0].__class__.__name__ == "InductionExpr":
                                    custom_value_str = "i*%d+%d" % (r.expr.operands[0].stride, r.expr.operands[0].init + r.expr.operands[1].value)

                            formatting['custom_values_str'][ident] = custom_value_str

                            if 'values_style' not in formatting: formatting['values_style'] = { }
                            formatting['values_style'][ident] = 'curly'

            self._label = self.operand.render(formatting=formatting)[0]
            self._label_width = len(self._label) * self._config.disasm_font_width

        if self.variable is not None:
            self._variable_ident_width = len(self._variable_ident) * self._config.disasm_font_width
        else:
            self._variable_ident_width = 0

        self._update_size()

    def _update_size(self):
        self._width = self._label_width
        if self.disasm_view.show_variable_identifier and self._variable_ident_width:
            self._width += self.VARIABLE_IDENT_SPACING + self._variable_ident_width
        if self._branch_targets_text_width:
            self._width += self.BRANCH_TARGETS_SPACING + self._branch_targets_text_width
        self._height = self._config.disasm_font_height

    def _pick_variable(self, variable_and_offsets):
        """
        Pick the corresponding variable for the current operand.

        :param list variable_and_offsets:   A list of variables and the offsets into each variable.
        :return:                            A tuple of variable and the offset.
        :rtype:                             tuple
        """

        if isinstance(self.operand, MemoryOperand):
            if len(variable_and_offsets) > 1:
                l.error("Instruction %#x has two memory operands. Please report it on GitHub.", self.insn.addr)
            return variable_and_offsets[0]

        elif isinstance(self.operand, RegisterOperand):
            # there might be multiple register-type variables for an instruction. pick the right one is... not easy

            the_reg = self.operand.register
            if the_reg is None:
                # huh, it does not have a Register child
                return None, None

            reg_name = the_reg.reg
            arch = self.workspace.instance.project.arch

            if len(variable_and_offsets) == 1:
                # only one candidate...
                var, offset = variable_and_offsets[0]
                if arch.registers[reg_name][0] == var.reg:
                    return var, offset
                return None, None

            if self.operand_index > 0:
                # this is the source operand
                # which variable is read here?
                for var, offset in variable_and_offsets:
                    if arch.registers[reg_name][0] == var.reg:
                        if self._variable_has_access(var, self.insn.addr, 'read'):
                            return var, offset

                l.debug('Cannot find any source variable for operand %d at instruction %#x.',
                        self.operand_index,
                        self.insn.addr
                        )
                return None, None

            # this is the destination operand
            # which variable is written here?
            for var, offset in variable_and_offsets:
                if arch.registers[reg_name][0] == var.reg:
                    if self._variable_has_access(var, self.insn.addr, 'write'):
                        return var, offset

            l.debug('Cannot find any destination variable for operand %d at instruction %#x.',
                    self.operand_index,
                    self.insn.addr
                    )
            # just return the first one
            return None, None

        else:
            # what's this type? why am I here?
            l.error('_pick_variable: Unsupported operand type %s.', self.operand.__class__)

            return None, None


    def _variable_has_access(self, variable, ins_addr, access_type):

        if variable not in self.variable_manager[self.func_addr]._variable_accesses:
            l.error('Variable %s does not have any accessing records.', variable)
            return False

        accesses = self.variable_manager[self.func_addr]._variable_accesses[variable]
        for access in accesses:
            if access.location.ins_addr == ins_addr and access.access_type == access_type:
                return True

        return False
