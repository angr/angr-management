
from PySide.QtGui import QHBoxLayout, QMenu, QApplication
from PySide.QtCore import Qt, QSize

from ...utils import locate_function
from ...data.function_graph import FunctionGraph
from ..widgets.qdisasm_graph import QDisasmGraph
from ..dialogs.jumpto import JumpTo
from ..dialogs.rename_label import RenameLabel
from ..dialogs.new_path import NewPath
from ..menus.disasm_insn_context_menu import DisasmInsnContextMenu
from .view import BaseView


class DisassemblyView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(DisassemblyView, self).__init__('disassembly', workspace, *args, **kwargs)

        self.caption = 'Disassembly'

        self._flow_graph = None

        self._insn_menu = None

        self._insn_addr_on_context_menu = None

        self._init_widgets()
        self._init_menus()

    def reload(self):
        pass

    #
    # Properties
    #

    @property
    def disasm(self):
        return self._flow_graph.disasm

    #
    # UI
    #

    def instruction_context_menu(self, insn, pos):

        self._insn_addr_on_context_menu = insn.addr

        # pass in the instruction address
        self._insn_menu.insn_addr = insn.addr
        # pop up the menu
        self._insn_menu.qmenu().exec_(pos)

        self._insn_addr_on_context_menu = None

    def popup_jumpto_dialog(self):
        JumpTo(self, None).exec_()

    def popup_rename_label_dialog(self):
        label_addr = self._address_in_selection()
        if label_addr is None:
            return

        dialog = RenameLabel(self, label_addr, None)
        dialog.exec_()

    def popup_newpath_dialog(self):
        addr = self._address_in_selection()
        if addr is None:
            return

        dialog = NewPath(self.workspace, addr, parent=None)
        dialog.exec_()

    #
    # Public methods
    #

    def display_function(self, function):
        # clear existing selected instructions
        self._flow_graph.selected_insns.clear()

        self._flow_graph.function_graph = FunctionGraph(function=function)

    def toggle_instruction_selection(self, insn_addr):
        """
        Toggle the selection state of an instruction in the disassembly view.

        :param int insn_addr: Address of the instruction to toggle.
        :return:              None
        """

        if insn_addr in self._flow_graph.selected_insns:
            self._flow_graph.unselect_instruction(insn_addr)
        else:
            self._flow_graph.select_instruction(insn_addr, unique=QApplication.keyboardModifiers() & Qt.CTRL == 0)
            self._flow_graph.show_instruction(insn_addr)

    def jump_to(self, addr):
        function = locate_function(self.workspace.instance, addr)
        if function is not None:
            self.display_function(function)
            self.toggle_instruction_selection(addr)
            return True
        else:
            return False

    def rename_label(self, addr, new_name):
        if self._flow_graph.disasm is not None:
            kb = self._flow_graph.disasm.kb
            if new_name == '':
                if addr in kb.labels:
                    del kb.labels[addr]
            else:
                kb.labels[addr] = new_name

            # redraw the current block
            self._flow_graph.update_label(addr)

    def sizeHint(self):
        return QSize(800, 800)

    #
    # Initialization
    #

    def _init_widgets(self):

        self._flow_graph = QDisasmGraph(self.workspace, self)

        hlayout = QHBoxLayout()
        hlayout.addWidget(self._flow_graph)

        self.setLayout(hlayout)

    def _init_menus(self):

        self._insn_menu = DisasmInsnContextMenu(self)

    #
    # Utils
    #

    def _address_in_selection(self):
        if self._insn_addr_on_context_menu is not None:
            return self._insn_addr_on_context_menu
        elif len(self._flow_graph.selected_insns) == 1:
            return next(iter(self._flow_graph.selected_insns))
        else:
            return None