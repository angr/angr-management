
from PySide.QtGui import QFrame, QLabel, QHBoxLayout, QSizePolicy, QCursor
from PySide.QtCore import Qt, SIGNAL

from .qoperand import QOperand


class QInstruction(QFrame):
    def __init__(self, workspace, disasm_view, disasm, insn, out_branch, parent):
        super(QInstruction, self).__init__(parent)

        # initialization
        self.workspace = workspace
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.insn = insn
        self.out_branch = out_branch

        self.selected = False

        self._init_widgets()

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.connect(self, SIGNAL('customContextMenuRequested(QPoint)'), self._on_context_menu)

    def mousePressEvent(self, mouse_event):
        if mouse_event.button() == Qt.LeftButton:
            # left click
            self.disasm_view.toggle_instruction_selection(self.insn.addr)

            return

        super(QInstruction, self).mousePressEvent(mouse_event)

    def select(self):
        if not self.selected:
            self.toggle_select()

    def unselect(self):
        if self.selected:
            self.toggle_select()

    def toggle_select(self):
        self.selected = not self.selected
        if self.selected:
            self.setProperty('class', 'insn_selected')
        else:
            self.setProperty('class', '')
        self.style().unpolish(self)
        self.style().polish(self)

    def _init_widgets(self):

        layout = QHBoxLayout()

        # address

        addr_label = QLabel(self)
        addr_label.setText('%08x' % self.insn.addr)
        addr_label.setProperty('class', 'insn_addr')
        addr_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        layout.addWidget(addr_label)

        # mnemonic

        mnemonic_label = QLabel(self)
        mnemonic_label.setText(self.insn.mnemonic.render()[0])
        mnemonic_label.setProperty('class', 'insn')
        mnemonic_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        layout.addWidget(mnemonic_label)

        # operands
        for i, operand in enumerate(self.insn.operands):
            is_branch_target = self.insn.type in ('branch', 'call') and i == self.insn.branch_target_operand
            is_indirect_branch = self.insn.branch_type == 'indirect'
            branch_targets = (self.out_branch.targets if self.out_branch is not None else None) \
                if is_branch_target else None
            is_last = i == len(self.insn.operands) - 1
            operand = QOperand(self.workspace, self.disasm_view, self.disasm, self.insn, operand, i, is_branch_target,
                               is_indirect_branch, branch_targets, is_last, self
                               )

            layout.addWidget(operand)

        layout.addStretch(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def _on_context_menu(self, pos):
        self.disasm_view.instruction_context_menu(self.insn, QCursor.pos())
