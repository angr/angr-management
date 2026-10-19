from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QFrame, QGridLayout, QLabel, QScrollArea, QSizePolicy, QVBoxLayout

from angrmanagement.config import Conf
from angrmanagement.present.symexec import ARCH_REGISTERS

from .qast_viewer import QASTViewer

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

log = logging.getLogger(__name__)


class QRegisterViewer(QFrame):
    """The registers of the selected state."""

    ARCH_REGISTERS = ARCH_REGISTERS

    def __init__(self, state, parent, workspace: Workspace) -> None:
        super().__init__(parent)

        self._state = state
        self.workspace = workspace

        self._registers = {}

        self._state.am_subscribe(self._watch_state)

    #
    # Overridden methods
    #

    def sizeHint(self):  # pylint: disable=no-self-use
        return QSize(100, 100)

    #
    # Public methods
    #

    def reload(self) -> None:
        for reg_name, reg_ctrl in self._registers.items():
            if self._state.am_none:
                reg_ctrl.ast = None
            else:
                reg_ctrl.ast = self._state.registers.load(reg_name, disable_actions=True, inspect=False)

    #
    # Private methods
    #

    def _init_widgets(self) -> None:
        if self._state.am_none:
            return

        if self._state.arch.name not in self.ARCH_REGISTERS:
            log.error("Architecture %s is not listed in QRegisterViewer.ARCH_REGISTERS.", self._state.arch.name)
            return

        layout = QGridLayout()
        area = QScrollArea()
        area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        area.setWidgetResizable(True)

        regs = self.ARCH_REGISTERS[self._state.arch.name]

        # common ones
        common_regs = regs["common"]

        for row, reg_name in enumerate(common_regs):
            lbl_reg_name = QLabel(self)
            lbl_reg_name.setFont(Conf.symexec_font)
            lbl_reg_name.setText(reg_name)
            lbl_reg_name.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            layout.addWidget(lbl_reg_name, row, 0)

            reg_value = QASTViewer(None, parent=self, workspace=self.workspace)
            self._registers[reg_name] = reg_value
            layout.addWidget(reg_value, row, 1)

        layout.setColumnStretch(1, 1)
        layout.setSpacing(0)
        layout.setContentsMargins(2, 2, 2, 2)

        # the container
        container = QFrame()
        container.setAutoFillBackground(True)
        palette = container.palette()
        palette.setColor(container.backgroundRole(), Conf.palette_base)
        container.setPalette(palette)
        container.setLayout(layout)

        area.setWidget(container)

        base_layout = QVBoxLayout()
        base_layout.addWidget(area)
        self.setLayout(base_layout)

    def _watch_state(self, **_) -> None:
        if not self._registers:
            self._init_widgets()

        self.reload()
