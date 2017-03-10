
import logging

from PySide.QtGui import QFrame, QLabel, QVBoxLayout, QHBoxLayout, QScrollArea, QSizePolicy
from PySide.QtCore import Qt, QSize

from .qast_viewer import QASTViewer

l = logging.getLogger('ui.widgets.qregister_viewer')


class QRegisterViewer(QFrame):

    ARCH_REGISTERS = {
        'X86': {
            'common': [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip' ]
        },
        'AMD64': {
            'common': [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'rip' ]
        }
    }

    def __init__(self, parent):
        super(QRegisterViewer, self).__init__(parent)

        self._state = None

        self._registers = { }

    #
    # Properties
    #

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, v):
        self._state = v

        if not self._registers:
            self._init_widgets()

        self.reload()

    #
    # Overridden methods
    #

    def sizeHint(self, *args, **kwargs):
        return QSize(100, 100)

    #
    # Public methods
    #

    def reload(self):

        state = self._state

        for reg_name, reg_ctrl in self._registers.iteritems():
            reg_ctrl.ast = getattr(state.regs, reg_name)

    #
    # Private methods
    #

    def _init_widgets(self):

        state = self._state

        if state.arch.name not in self.ARCH_REGISTERS:
            l.error("Architecture %s is not listed in QRegisterViewer.ARCH_REGISTERS.", self._arch.name)
            return

        layout = QVBoxLayout()
        area = QScrollArea()
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        regs = self.ARCH_REGISTERS[state.arch.name]

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

            reg_value = QASTViewer(None, self)
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
