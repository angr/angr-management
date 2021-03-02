import logging

from PySide2.QtWidgets import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QSizePolicy
from PySide2.QtCore import Qt, QSize

from .qast_viewer import QASTViewer

l = logging.getLogger('ui.widgets.qregister_viewer')


class QRegisterViewer(QFrame):

    ARCH_REGISTERS = {
        'X86': {
            'common': [
                'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip'
            ]
        },
        'AMD64': {
            'common': [
                'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12',
                'r13', 'r14', 'r15'
            ]
        },
        'MIPS32': {
            'common': [
                'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7', 't8', 't9',
                's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 'gp', 'sp', 'ra', 'pc'
            ]
        },
        'ARM': {
            'common': [
                'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
            ]
        },
    }

    ARCH_REGISTERS['ARMEL'] = ARCH_REGISTERS['ARM']
    ARCH_REGISTERS['ARMHF'] = ARCH_REGISTERS['ARM']

    def __init__(self, state, parent, workspace):
        super(QRegisterViewer, self).__init__(parent)

        self._state = state
        self.workspace = workspace

        self._registers = { }

        self._state.am_subscribe(self._watch_state)

    #
    # Overridden methods
    #

    def sizeHint(self, *args, **kwargs):
        return QSize(100, 100)

    #
    # Public methods
    #

    def reload(self):
        for reg_name, reg_ctrl in self._registers.items():
            if self._state.am_none:
                reg_ctrl.ast = None
            else:
                reg_ctrl.ast = self._state.registers.load(reg_name, disable_actions=True, inspect=False)

    #
    # Private methods
    #

    def _init_widgets(self):
        if self._state.am_none:
            return

        if self._state.arch.name not in self.ARCH_REGISTERS:
            l.error("Architecture %s is not listed in QRegisterViewer.ARCH_REGISTERS.", self._state.arch.name)
            return

        layout = QVBoxLayout()
        area = QScrollArea()
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        regs = self.ARCH_REGISTERS[self._state.arch.name]

        # common ones
        common_regs = regs['common']

        for reg_name in common_regs:
            sublayout = QHBoxLayout()

            lbl_reg_name = QLabel(self)
            lbl_reg_name.setProperty('class', 'reg_viewer_label')
            lbl_reg_name.setText(reg_name)
            lbl_reg_name.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            sublayout.addWidget(lbl_reg_name)

            sublayout.addSpacing(10)
            reg_value = QASTViewer(None, parent=self, workspace=self.workspace)
            self._registers[reg_name] = reg_value
            sublayout.addWidget(reg_value)

            layout.addLayout(sublayout)

        layout.setSpacing(0)
        layout.addStretch(0)
        layout.setContentsMargins(2, 2, 2, 2)

        # the container
        container = QFrame()
        container.setAutoFillBackground(True)
        palette = container.palette()
        palette.setColor(container.backgroundRole(), Qt.white)
        container.setPalette(palette)
        container.setLayout(layout)

        area.setWidget(container)

        base_layout = QVBoxLayout()
        base_layout.addWidget(area)
        self.setLayout(base_layout)

    def _watch_state(self, **kwargs):
        if not self._registers:
            self._init_widgets()

        self.reload()
