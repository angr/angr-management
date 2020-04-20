
from PySide2.QtCore import Qt


class QDisassemblyBaseControl:
    """
    The base control class of QLinearViewer and QDisassemblyGraph. Implements or declares common shorthands and methods.
    """

    def __init__(self, workspace, disasm_view, base_cls):
        self.workspace = workspace
        self.disasm_view = disasm_view
        self._base_cls = base_cls

        self._insaddr_to_block = { }

    @property
    def infodock(self):
        return self.disasm_view.infodock

    def refresh(self):
        """
        Recalculate sizes and positions of subitems, and trigger a refresh on every subitem (in order to reload text,
        etc.)

        :return:    None
        """
        raise NotImplementedError()

    def reload(self):
        raise NotImplementedError()

    def show_instruction(self, insn_addr, insn_pos=None, centering=False, use_block_pos=False):
        raise NotImplementedError()

    #
    # Public methods
    #

    def get_selected_operand_info(self):
        if not self.infodock.selected_operands:
            return None

        # get the first operand
        ins_addr, operand_idx = next(iter(self.infodock.selected_operands))
        block = self._insaddr_to_block.get(ins_addr, None)
        if block is not None:
            operand = block.addr_to_insns[ins_addr].get_operand(operand_idx)
            return block, ins_addr, operand

        return None

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

        self._base_cls.keyPressEvent(self, event)
