
from PySide.QtGui import QFrame, QLabel, QHBoxLayout, QSizePolicy


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


class QOperand(QFrame):
    def __init__(self, workspace, disasm_view, disasm, insn, operand, operand_index, is_branch_target, is_indirect_branch,
                 branch_targets, is_last, parent):
        super(QOperand, self).__init__(parent)

        self.workspace = workspace
        self.disasm_view = disasm_view
        self.disasm = disasm
        self.insn = insn
        self.operand = operand
        self.operand_index = operand_index
        self.is_branch_target = is_branch_target
        self.is_indirect_branch = is_indirect_branch
        self.branch_targets = branch_targets
        self.is_last = is_last

        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setContentsMargins(0, 0, 0, 0)

        self._init_widgets()

    def _init_widgets(self):

        layout = QHBoxLayout()

        if self.is_branch_target:
            # a branch instruction
            if self.is_indirect_branch:
                label = QLabel(self)
                label.setText(self.operand.render()[0])
                label.setProperty('class', 'insn')

                layout.addWidget(label)

            else:
                if self.branch_targets is not None and next(iter(self.branch_targets)) in self.disasm.kb.functions:
                    # jumping to a function
                    is_target_func = True
                else:
                    # jumping to a non-function address
                    is_target_func = False
                label = QOperandBranchTarget(self.disasm_view,
                                             self.operand.render()[0],
                                             None if self.branch_targets is None else next(iter(self.branch_targets)),
                                             is_target_func,
                                             self
                                             )

                layout.addWidget(label)

        else:
            # not a branch
            label = QLabel(self)
            label.setText(self.operand.render()[0])
            label.setProperty('class', 'insn')

            layout.addWidget(label)

        if not self.is_last:
            delimiter = QLabel(self)
            delimiter.setText(',')
            delimiter.setProperty('class', 'insn')

            layout.addWidget(delimiter)

        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)