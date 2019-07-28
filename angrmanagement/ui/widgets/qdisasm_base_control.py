

class QDisassemblyBaseControl:
    """
    The base control class of QLinearViewer and QDisassemblyGraph. Implements or declares common shorthands and methods.
    """

    def __init__(self, workspace, disasm_view):
        self.workspace = workspace
        self.disasm_view = disasm_view

    def refresh(self):
        """
        Recalculate sizes and positions of subitems, and trigger a refresh on every subitem (in order to reload text,
        etc.)

        :return:    None
        """
        raise NotImplementedError()

    def show_instruction(self, insn_addr, item=None, centering=False, use_block_pos=False):
        raise NotImplementedError()
