
from ...data.object_container import ObjectContainer


class OperandHighlightMode:
    SAME_IDENT = 0
    SAME_TEXT = 1


class OperandDescriptor:

    __slots__ = ('text', 'num_value', 'func_addr', 'variable_ident', )

    def __init__(self, text, num_value, func_addr=None, variable_ident=None):
        self.text = text
        self.num_value = num_value
        self.func_addr = func_addr
        self.variable_ident = variable_ident


class InfoDock:
    """
    Stores information associated to a disassembly view. Such information will be shared between the graph view and the
    linear view.
    """

    def __init__(self, disasm_view):
        self.disasm_view = disasm_view

        self.induction_variable_analysis = None
        self.variable_manager = None

        self.highlight_mode = OperandHighlightMode.SAME_IDENT  # default highlight mode

        self.selected_insns = ObjectContainer(set(), 'The currently selected instructions')
        self.selected_operands = ObjectContainer({}, 'The currently selected instruction operands')
        self.selected_blocks = ObjectContainer(set(), 'The currently selected blocks')
        self.hovered_block = ObjectContainer(None, 'The currently hovered block')
        self.hovered_edge = ObjectContainer(None, 'The currently hovered edge')
        self.selected_labels = ObjectContainer(set(), 'The currently selected labels')

    @property
    def smart_highlighting(self):
        return self.highlight_mode == OperandHighlightMode.SAME_IDENT

    @smart_highlighting.setter
    def smart_highlighting(self, v):
        if v:
            self.highlight_mode = OperandHighlightMode.SAME_IDENT
        else:
            self.highlight_mode = OperandHighlightMode.SAME_TEXT

    def initialize(self):
        self.selected_blocks.clear()
        self.selected_insns.clear()
        self.selected_operands.clear()
        self.hovered_block.am_obj = None

    def hover_edge(self, src_addr, dst_addr):
        self.hovered_edge.am_obj = src_addr, dst_addr
        self.hovered_edge.am_event()

    def unhover_edge(self, src_addr, dst_addr):
        if self.hovered_edge.am_obj == (src_addr, dst_addr):
            self.hovered_edge.am_obj = None
            self.hovered_edge.am_event()

    def hover_block(self, block_addr):
        self.hovered_block.am_obj = block_addr
        self.hovered_block.am_event()

    def unhover_block(self, block_addr):
        if self.hovered_block.am_obj == block_addr:
            self.hovered_block.am_obj = None
            self.hovered_block.am_event()

    def clear_hovered_block(self):
        self.hovered_block.am_obj = None
        self.hovered_block.am_event()

    def select_block(self, block_addr):
        self.selected_blocks.clear()  # selecting one block at a time
        self.selected_blocks.add(block_addr)
        self.selected_blocks.am_event()

    def unselect_block(self, block_addr):
        if block_addr in self.selected_blocks:
            self.selected_blocks.remove(block_addr)
            self.selected_blocks.am_event()

    def select_instruction(self, insn_addr, unique=True, insn_pos=None):
        self.unselect_all_labels()
        if insn_addr not in self.selected_insns:
            if unique:
                # unselect existing ones
                self.unselect_all_instructions()
                self.selected_insns.add(insn_addr)
            else:
                self.selected_insns.add(insn_addr)
            self.disasm_view.current_graph.show_instruction(insn_addr, insn_pos=insn_pos)
            self.selected_insns.am_event(insn_addr=insn_addr)

    def unselect_instruction(self, insn_addr):
        if insn_addr in self.selected_insns:
            self.selected_insns.remove(insn_addr)
            self.selected_insns.am_event()

    def unselect_all_instructions(self):
        if self.selected_insns:
            self.selected_insns.clear()
            self.selected_insns.am_event()

    def select_operand(self, ins_addr, operand_index, operand, unique=False):
        """
        Mark an operand as selected.

        :param int ins_addr:                Address of the instruction.
        :param int operand_index:           Index of the operand.
        :param OperandDescriptor operand:   Data of the operand.
        :param bool unique:                 If this is a unique selection or not.
        :return:                            None
        """

        tpl = ins_addr, operand_index
        if tpl not in self.selected_operands:
            if unique:
                self.selected_operands.clear()
            self.selected_operands[tpl] = operand
            self.selected_operands.am_event()

    def unselect_operand(self, insn_addr, operand_idx):

        if (insn_addr, operand_idx) in self.selected_operands:
            self.selected_operands.pop((insn_addr, operand_idx))
            self.selected_operands.am_event()

    def select_label(self, label_addr):
        # only one label can be selected at a time
        self.selected_labels.clear()
        self.selected_labels.add(label_addr)
        self.selected_labels.am_event()

    def unselect_label(self, label_addr):
        if label_addr in self.selected_labels:
            self.selected_labels.remove(label_addr)
            self.selected_labels.am_event()

    def unselect_all_labels(self):
        self.selected_labels.clear()
        self.selected_labels.am_event()

    def toggle_instruction_selection(self, insn_addr, insn_pos=None, unique=False):
        """
        Toggle the selection state of an instruction in the disassembly view.

        :param int insn_addr: Address of the instruction to toggle.
        :return:              None
        """

        if insn_addr in self.selected_insns:
            self.unselect_instruction(insn_addr)
        else:
            self.select_instruction(insn_addr, unique=unique, insn_pos=insn_pos)

    def toggle_operand_selection(self, insn_addr, operand_idx, operand, insn_pos=None, unique=False):
        """
        Toggle the selection state of an operand of an instruction in the disassembly view.

        :param int insn_addr:   Address of the instruction to toggle.
        :param int operand_idx: The operand to toggle.
        :param operand:         The operand instance.
        :return:                True if this operand is now selected, False otherwise.
        :rtype:                 bool
        """

        if (insn_addr, operand_idx) in self.selected_operands:
            self.unselect_operand(insn_addr, operand_idx)
            return False
        else:
            self.select_operand(insn_addr, operand_idx, operand, unique=unique)
            self.disasm_view.current_graph.show_instruction(insn_addr, insn_pos=insn_pos)
            return True

    def clear_selection(self):
        self.selected_blocks.clear()
        self.selected_blocks.am_event()

        self.selected_insns.clear()
        self.selected_insns.am_event()

        self.selected_operands.clear()
        self.selected_operands.am_event()

    def is_edge_hovered(self, src_addr, dst_addr):
        return self.hovered_edge.am_obj == (src_addr, dst_addr)

    def is_block_hovered(self, block_addr):
        return block_addr == self.hovered_block.am_obj

    def is_block_selected(self, block_addr):
        return block_addr in self.selected_blocks

    def is_instruction_selected(self, ins_addr):
        """
        Check if an instruction at @ins_addr is currently selected or not.

        :param int ins_addr:    Address of the instruction.
        :return:                True if it is selected, False otherwise.
        :rtype:                 bool
        """
        return ins_addr in self.selected_insns

    def is_operand_selected(self, ins_addr, operand_index):
        """
        Check if an operand at @ins_addr and @operand_index is currently selected or not.

        :param int ins_addr:        Address of the instruction
        :param int operand_index:   Index of the operand.
        :return:                    bool
        """
        return (ins_addr, operand_index) in self.selected_operands

    def is_label_selected(self, label_addr):
        return label_addr in self.selected_labels

    def should_highlight_operand(self, selected, operand):
        if selected is None:
            return False

        if self.highlight_mode == OperandHighlightMode.SAME_TEXT or selected.variable is None:
            # when there is no related variable, we highlight as long as they have the same text
            return operand.text == selected.text
        elif self.highlight_mode == OperandHighlightMode.SAME_IDENT:
            if selected.variable is not None and operand.variable is not None:
                return selected.variable.ident == operand.variable.ident

        return False
