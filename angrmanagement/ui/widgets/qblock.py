
from PySide.QtGui import QFrame, QVBoxLayout

from angr.analyses.disassembly import Instruction

from ...utils import (
    get_label_text, get_block_objects, address_to_text, get_out_branches_for_insn,
    get_string_for_display, should_display_string_label,
)
from .qinstruction import QInstruction
from .qblock_label import QBlockLabel


class QBlock(QFrame):
    def __init__(self, workspace, disasm_view, disasm, addr, cfg_nodes, out_branches, parent=None):
        super(QBlock, self).__init__(parent)

        # initialization
        self.workspace = workspace
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.addr = addr
        self.cfg_nodes = cfg_nodes
        self.out_branches = out_branches

        self.addr_to_insns = { }
        self.addr_to_labels = { }

        self._init_widgets()

    #
    # Public methods
    #

    def update_label(self, label_addr):
        label = self.addr_to_labels.get(label_addr, None)
        if label is not None:
            label.label = self.disasm.kb.labels[label_addr]
        else:
            raise Exception('Label at address %#x is not found.' % label_addr)

    def instruction_position(self, insn_addr):
        if insn_addr in self.addr_to_insns:
            insn = self.addr_to_insns[insn_addr]
            return insn.pos()

        return None

    #
    # Initialization
    #

    def _init_widgets(self):

        block_objects = get_block_objects(self.disasm, self.cfg_nodes)

        all_widgets = [ ]

        for obj in block_objects:
            if isinstance(obj, Instruction):
                out_branch = get_out_branches_for_insn(self.out_branches, obj.addr)
                insn = QInstruction(self.workspace, self.disasm_view, self.disasm, obj, out_branch, self)
                all_widgets.append(insn)
                self.addr_to_insns[obj.addr] = insn

            elif isinstance(obj, tuple):
                # label
                addr, text = obj
                label = QBlockLabel(addr, text, self)
                all_widgets.append(label)
                self.addr_to_labels[addr] = label

        layout = QVBoxLayout()
        for w in all_widgets:
            layout.addWidget(w)
        layout.setSpacing(2)
        layout.setContentsMargins(5,5,5,5)
        self.setLayout(layout)
