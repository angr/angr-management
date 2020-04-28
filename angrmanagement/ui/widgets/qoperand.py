import logging

from PySide2.QtWidgets import QApplication
from PySide2.QtGui import QPainter, QColor
from PySide2.QtCore import Qt, QRectF, QPointF

from angr.analyses.disassembly import ConstantOperand, RegisterOperand, MemoryOperand, Value

from ...logic.disassembly.info_dock import OperandDescriptor, OperandHighlightMode
from .qgraph_object import QCachedGraphicsItem

l = logging.getLogger('ui.widgets.qoperand')


class QOperand(QCachedGraphicsItem):

    BRANCH_TARGETS_SPACING = 5
    LABEL_VARIABLE_SPACING = 5
    VARIABLE_IDENT_SPACING = 5

    def __init__(self, workspace, func_addr, disasm_view, disasm, infodock, insn, operand, operand_index,
                 is_branch_target, is_indirect_branch, branch_targets, config, parent=None, container=None):
        super().__init__(parent=parent, container=container)

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

        self._cachy = None

        self._config = config

        # "widgets"
        self._label = None
        self._label_width = None
        self._variable_label = None
        self._variable_label_width = None
        self._variable_ident = None
        self._variable_ident_width = None
        self._branch_target = None
        self._branch_targets = None
        self._branch_targets_text = None
        self._branch_targets_text_width = None
        self._is_target_func = None

        self._width = None
        self._height = None

        self._init_widgets()

    #
    # Properties
    #

    @property
    def text(self):
        return self._label

    @property
    def is_constant(self):
        return isinstance(self.operand, ConstantOperand)

    @property
    def constant_value(self):
        if self.is_constant:
            return self.operand.cs_operand.imm
        return None

    @property
    def is_constant_memory(self):
        return (isinstance(self.operand, MemoryOperand) and
                len(self.operand.values) == 1 and
                isinstance(self.operand.values[0], Value) and
                isinstance(self.operand.values[0].val, int)
                )

    @property
    def constant_memory_value(self):
        if self.is_constant_memory:
            return self.operand.values[0].val
        return None

    @property
    def selected(self):
        return self.infodock.is_operand_selected(self.insn.addr, self.operand_index)

    @property
    def operand_descriptor(self):
        return OperandDescriptor(self.text, None,
                                 func_addr=self.func_addr,
                                 variable_ident=self.variable.ident if self.variable is not None else None)

    #
    # Event handlers
    #

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            selected = self.infodock.toggle_operand_selection(
                self.insn.addr,
                self.operand_index,
                self.operand_descriptor,
                insn_pos=self.parentItem().scenePos(),
                unique=QApplication.keyboardModifiers() != Qt.ControlModifier
            )
            if selected:
                # select the current instruction, too
                self.infodock.select_instruction(self.insn.addr, insn_pos=QPointF(self.x(), self.y()), unique=True)
        else:
            super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        button = event.button()
        if button == Qt.LeftButton:
            if self._branch_target is not None:
                self.disasm_view.jump_to(self._branch_target, src_ins_addr=self.insn.addr)
                return
            if self.is_constant:
                self.disasm_view.jump_to(self.constant_value, src_ins_addr=self.insn.addr)
                return
            if self.is_constant_memory:
                self.disasm_view.jump_to(self.constant_memory_value, src_ins_addr=self.insn.addr)
        else:
            super().mouseDoubleClickEvent(event)

    #
    # Public methods
    #

    def refresh(self):
        self._update_size()
        self.recalculate_size()

    def paint(self, painter, option, widget): #pylint: disable=unused-argument
        if self.selected:
            painter.setPen(self._config.disasm_view_operand_select_color)
            painter.setBrush(self._config.disasm_view_operand_select_color)
            painter.drawRect(0, 0, self.width, self.height)
        else:
            for _, selected_operand_desc in self.infodock.selected_operands.items():
                if self._equals_for_highlighting_purposes(selected_operand_desc):
                    painter.setBrush(self._config.disasm_view_operand_highlight_color)
                    painter.setPen(self._config.disasm_view_operand_highlight_color)
                    painter.drawRect(0, 0, self.width, self.height)
                    break

        if self._branch_target or self._branch_targets:
            if self._is_target_func:
                painter.setPen(self._config.disasm_view_target_addr_color)
            else:
                painter.setPen(self._config.disasm_view_antitarget_addr_color)
        else:
            if self.disasm_view.show_variable and self.variable is not None:
                # show-variable is enabled and this operand has a linked variable
                #fallback = True
                #if self.infodock.induction_variable_analysis is not None:
                #    r = self.infodock.induction_variable_analysis.variables.get(self.variable.ident, None)
                #    if r is not None and r.expr.__class__.__name__ == "InductionExpr":
                #        painter.setPen(Qt.darkYellow)
                #        fallback = False
                pass

            painter.setPen(QColor(0x00, 0x00, 0x80))

        painter.setRenderHints(
                QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        painter.setFont(self._config.disasm_font)
        y = self._config.disasm_font_ascent

        # draw label
        # [rax]
        text = self._label
        x = self._label_width
        painter.drawText(0, y, text)

        # draw variable
        # {s_10}
        if self.disasm_view.show_variable and self._variable_label:
            x += self.LABEL_VARIABLE_SPACING * self.currentDevicePixelRatioF()
            painter.setPen(QColor(0x00, 0x80, 0x00))
            painter.drawText(x, y, self._variable_label)
            painter.setPen(QColor(0x00, 0x00, 0x80))
            x += self._variable_label_width

        # draw additional branch targets
        if self._branch_targets_text:
            painter.setPen(Qt.darkYellow)
            x += self.BRANCH_TARGETS_SPACING * self.currentDevicePixelRatioF()
            painter.drawText(x, y, self._branch_targets_text)
            x += self._branch_targets_text_width

        if self.variable is not None and self.disasm_view.show_variable_identifier:
            x += self.VARIABLE_IDENT_SPACING
            painter.setPen(Qt.darkGreen)
            painter.drawText(x, y, self._variable_ident)
            x += self._variable_ident_width

        # restores the color
        painter.setPen(QColor(0, 0, 0x80))

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

        imm = self.constant_value
        if imm is not None and imm in branch_targets:
            # problem solved
            return imm
        else:
            # umm why?
            pass

        # try to render it
        rendered = operand.render()[0]
        for t in branch_targets:
            if "%x" % t == rendered or "%#x" % t == rendered:
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
                self._is_target_func = is_target_func

                self._branch_targets = self.branch_targets
                first_n_targets = self._first_n_branch_targets(self._branch_targets, 3)
                if first_n_targets:
                    targets = [ ]
                    for t in first_n_targets:
                        txt = None
                        if is_target_func:
                            # try to get a function
                            try:
                                target_func = self.disasm.kb.functions.get_by_addr(t)
                                txt = target_func.demangled_name
                            except KeyError:
                                pass
                        # is the address a label?
                        if txt is None and t in self.disasm.kb.labels:
                            txt = self.disasm.kb.labels[t]
                        if txt is None:
                            # use the hex text
                            txt = "%#08x" % t
                        targets.append(txt)
                    self._branch_targets_text = "[ " + ", ".join(targets) +  " ]"
                else:
                    self._branch_targets_text = "[ unknown ]"

                if self._branch_targets and len(self._branch_targets) == 1:
                    self._branch_target = next(iter(self._branch_targets))

            else:
                self._label = self.operand.render()[0]
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

            # without displaying variable
            self._label = self.operand.render(formatting=formatting)[0]

            if variable_sort:
                # try find the corresponding variable
                variable_and_offsets = self.variable_manager[self.func_addr].find_variables_by_insn(self.insn.addr,
                                                                                                    variable_sort
                                                                                                    )
                if variable_and_offsets:
                    variable, offset = self._pick_variable(variable_and_offsets)

                    if variable is not None:
                        self.variable = variable
                        self._variable_ident = "<%s>" % variable.ident
                        if offset is None:
                            offset = 0

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

                    # with variable displayed
                    if variable_sort == 'memory':
                        self._variable_label = self.operand.render(formatting=formatting)[0]
                    else:
                        self._variable_label = ''

        self._update_size()

    def _update_size(self):

        if self._label is not None:
            self._label_width = self._config.disasm_font_metrics.width(self._label) * self.currentDevicePixelRatioF()
        else:
            self._label_width = 0
        if self._branch_targets_text is not None:
            self._branch_targets_text_width = self._config.disasm_font_metrics.width(self._branch_targets_text) * self.currentDevicePixelRatioF()
        else:
            self._branch_targets_text_width = 0
        if self._variable_label is not None:
            self._variable_label_width = self._config.disasm_font_metrics.width(self._variable_label) * self.currentDevicePixelRatioF()
        else:
            self._variable_label_width = 0
        if self.variable is not None:
            self._variable_ident_width = self._config.disasm_font_metrics.width(self._variable_ident) * self.currentDevicePixelRatioF()
        else:
            self._variable_ident_width = 0

        self._width = self._label_width
        if self.disasm_view.show_variable and self._variable_label:
            self._width += self.LABEL_VARIABLE_SPACING * self.currentDevicePixelRatioF() + self._variable_label_width
        if self.disasm_view.show_variable_identifier and self._variable_ident_width:
            self._width += self.VARIABLE_IDENT_SPACING * self.currentDevicePixelRatioF() + self._variable_ident_width
        if self._branch_targets_text_width:
            self._width += self.BRANCH_TARGETS_SPACING * self.currentDevicePixelRatioF() + self._branch_targets_text_width
        self._height = self._config.disasm_font_height * self.currentDevicePixelRatioF()
        self.recalculate_size()

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

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

    def _equals_for_highlighting_purposes(self, other):
        """

        :param OperandDescriptor other: The other operand to compare with.
        :return:
        """

        if other is None:
            return False

        highlight_mode = self.infodock.highlight_mode

        if highlight_mode == OperandHighlightMode.SAME_TEXT or self.variable is None:
            # when there is no related variable, we highlight as long as they have the same text
            return other.text == self.text
        elif highlight_mode == OperandHighlightMode.SAME_IDENT:
            if self.variable is not None and other.variable_ident is not None:
                return self.func_addr == other.func_addr and self.variable.ident == other.variable_ident

        return False
