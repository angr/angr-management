from enum import Enum
from typing import TYPE_CHECKING, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

if TYPE_CHECKING:
    from angrmanagement.ui.views import DisassemblyView
    from angrmanagement.ui.widgets.qblock import QBlock
    from angrmanagement.ui.widgets.qoperand import QOperand


class DisassemblyLevel(Enum):
    MachineCode = 0
    LifterIR = 1
    AIL = 2


class QDisassemblyBaseControl:
    """
    The base control class of QLinearViewer and QDisassemblyGraph. Implements or declares common shorthands and methods.
    """

    def __init__(self, instance, disasm_view, base_cls):
        self.instance = instance
        self.disasm_view: DisassemblyView = disasm_view
        self._base_cls = base_cls
        self._insaddr_to_block = {}
        self._disassembly_level = disasm_view.disassembly_level

    @property
    def infodock(self):
        return self.disasm_view.infodock

    def refresh(self):
        """
        Recalculate sizes and positions of subitems, and trigger a refresh on every subitem (in order to reload text,
        etc.)

        :return:    None
        """
        raise NotImplementedError

    def reload(self):
        raise NotImplementedError

    def show_instruction(self, insn_addr, insn_pos=None, centering=False, use_block_pos=False, use_animation=False):
        raise NotImplementedError

    #
    # Public methods
    #

    def get_selected_operand_info(self) -> Optional[Tuple["QBlock", int, "QOperand"]]:
        if not self.infodock.selected_operands:
            return None

        # get the first operand
        ins_addr, operand_idx = next(iter(self.infodock.selected_operands))
        block = self._insaddr_to_block.get(ins_addr, None)
        if block is not None:
            operand = block.addr_to_insns[ins_addr].get_operand(operand_idx)
            return block, ins_addr, operand

        return None

    def set_disassembly_level(self, level: DisassemblyLevel):
        self._disassembly_level = level
        self.reload()

    #
    # Event handlers
    #

    def keyPressEvent(self, event):
        key = event.key()

        if key == Qt.Key_N:
            # rename a label
            self.disasm_view.popup_rename_label_dialog()
            return
        elif key == Qt.Key_X:
            # XRef
            # try to get a selected operand
            r = self.get_selected_operand_info()
            if r is not None:
                # xref to an operand
                _, ins_addr, operand = r
                self.disasm_view.parse_operand_and_popup_xref_dialog(ins_addr, operand)
                return

            # try to get a selected label
            if len(self.infodock.selected_labels) == 1:
                lbl_addr = next(iter(self.infodock.selected_labels))
                self.disasm_view.popup_xref_dialog(addr=lbl_addr, dst_addr=lbl_addr)
                return

            # try to get a selected variable
            if len(self.infodock.selected_variables) == 1:
                variable = next(iter(self.infodock.selected_variables))
                self.disasm_view.popup_xref_dialog(addr=0, variable=variable)
                return

            # message the user
            QMessageBox.critical(
                None,
                "Invalid selection for XRefs",
                "You must select an operand, a label, a variable, or a function header before requesting XRefs.",
            )

            return

        self._base_cls.keyPressEvent(self, event)
