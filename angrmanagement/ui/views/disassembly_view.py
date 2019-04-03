
from PySide2.QtWidgets import QVBoxLayout, QMenu, QApplication
from PySide2.QtCore import Qt, QSize

from ...data.instance import ObjectContainer
from ...utils import locate_function
from ...data.function_graph import FunctionGraph
from ...logic.disassembly import JumpHistory, InfoDock
from ..widgets import QDisasmGraph, QDisasmStatusBar, QLinearViewer
from ..dialogs.jumpto import JumpTo
from ..dialogs.rename_label import RenameLabel
from ..dialogs.set_comment import SetComment
from ..dialogs.new_state import NewState
from ..dialogs.xref import XRef
from ..menus.disasm_insn_context_menu import DisasmInsnContextMenu
from .view import BaseView


class DisassemblyView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(DisassemblyView, self).__init__('disassembly', workspace, *args, **kwargs)

        self.caption = 'Disassembly'

        self._show_address = True
        self._show_variable = False #True
        # whether we want to show identifier or not
        self._show_variable_ident = False

        self._linear_viewer = None  # type: QLinearViewer
        self._flow_graph = None  # type: QDisasmGraph
        self._statusbar = None
        self._jump_history = JumpHistory()
        self.infodock = InfoDock()
        self._variable_recovery_flavor = 'fast'
        self.variable_manager = None  # type: VariableManager
        self._current_function = ObjectContainer(None, 'The currently selected function')

        self._insn_menu = None

        self._insn_addr_on_context_menu = None

        self._init_widgets()
        self._init_menus()

    def reload(self):

        self.infodock.initialize()

        # Initialize the linear viewer
        # TODO: Relocate the logic to a better place
        self._linear_viewer.cfg = self.workspace.instance.cfg
        self._linear_viewer.cfb = self.workspace.instance.cfb
        self._linear_viewer.initialize()

    def save_image_to(self, path):
        if self._flow_graph is not None:
            self._flow_graph.save_image_to(path)

    def setFocus(self):
        self._flow_graph.setFocus()

    #
    # Properties
    #

    @property
    def disasm(self):
        return self._flow_graph.disasm

    @property
    def smart_highlighting(self):
        if self._flow_graph is None:
            return False
        if self.infodock is None:
            return False
        return self.infodock.smart_highlighting

    @property
    def show_address(self):
        return self._show_address

    @property
    def show_variable(self):
        return self._show_variable

    @property
    def show_variable_identifier(self):
        return self._show_variable_ident

    @property
    def variable_recovery_flavor(self):
        return self._variable_recovery_flavor

    @variable_recovery_flavor.setter
    def variable_recovery_flavor(self, v):
        if v in ('fast', 'accurate'):
            if v != self._variable_recovery_flavor:
                self._variable_recovery_flavor = v
                # TODO: Rerun the variable recovery analysis and update the current view

    @property
    def current_graph(self):
        if self._linear_viewer.isVisible():
            return self._linear_viewer
        else:
            return self._flow_graph

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
        JumpTo(self, parent=self).exec_()

    def popup_rename_label_dialog(self):
        label_addr = self._address_in_selection()
        if label_addr is None:
            return

        dialog = RenameLabel(self, label_addr, parent=self)
        dialog.exec_()

    def popup_comment_dialog(self):
        comment_addr = self._address_in_selection()
        if comment_addr is None:
            return

        dialog = SetComment(self, comment_addr, parent=self)
        dialog.exec_()

    def popup_newstate_dialog(self, asynch=True):
        addr = self._address_in_selection()
        if addr is None:
            return

        dialog = NewState(self.workspace.instance, addr=addr, create_simgr=True, parent=self)
        if asynch:
            dialog.show()
        else:
            dialog.exec_()

    def popup_xref_dialog(self, variable, asynch=True):

        dialog = XRef(self.variable_manager, variable, parent=self)
        if asynch:
            dialog.show()
        else:
            dialog.exec_()

    #
    # Public methods
    #

    def subscribe_insn_select(self, callback):
        """
        Appends the provided function to the list of callbacks to be called when an instruction is selected in the
        disassembly. The callback's parameters are:
            'graph': the `QBaseGraph` object
            'addr': integer address of the selected instruction
            'block': the `QBlock` containing the instruction
        :param callback: The callback function to call, which must accept **kwargs
        """
        self._linear_viewer.selected_insns.am_subscribe(callback)
        self._flow_graph.selected_insns.am_subscribe(callback)

    def display_disasm_graph(self):

        self._linear_viewer.hide()
        self._flow_graph.show()
        self._flow_graph.setFocus()

    def display_linear_viewer(self):

        self._flow_graph.hide()
        self._linear_viewer.show()
        self._linear_viewer._linear_view.setFocus()

        if self._current_function is not None:
            self._linear_viewer.navigate_to_addr(self._current_function.addr)

    def display_function(self, function):

        self._jump_history.jump_to(function.addr)
        self._display_function(function)

    def decompile_current_function(self):

        if self._current_function is not None:
            self.workspace.decompile_function(self._current_function)

    def toggle_smart_highlighting(self, enabled):
        """
        Toggle between the smart highlighting mode and the text-based highlighting mode.

        :param bool enabled: Enable smart highlighting.
        :return:             None
        """

        self.infodock.smart_highlighting = enabled

        self._flow_graph.refresh()
        self._linear_viewer.refresh()

    def toggle_show_address(self, show_address):
        """
        Toggle whether addresses are shown on disassembly graph.

        :param bool show_address: Whether the address should be shown or not. 
        :return:                  None
        """

        self._show_address = show_address

        self.current_graph.refresh()

    def toggle_show_variable(self, show_variable):
        """
        Toggle whether variables are shown on disassembly graph.

        :param bool show_variable: Whether the variable should be shown or not.
        :return:                   None
        """

        self._show_variable = show_variable

        self.current_graph.refresh()

    def toggle_show_variable_identifier(self, show_ident):
        """
        Toggle whether variable identifiers are shown on disassembly graph.

        :param bool show_ident: Whether variable identifiers should be shown or not.
        :return:                None
        """

        self._show_variable_ident = show_ident

        self.current_graph.refresh()

    def toggle_instruction_selection(self, insn_addr):
        """
        Toggle the selection state of an instruction in the disassembly view.

        :param int insn_addr: Address of the instruction to toggle.
        :return:              None
        """

        if insn_addr in self.current_graph.selected_insns:
            self.current_graph.unselect_instruction(insn_addr)
        else:
            self.current_graph.select_instruction(insn_addr, unique=QApplication.keyboardModifiers() & Qt.CTRL == 0)
            self.current_graph.show_instruction(insn_addr)

    def toggle_operand_selection(self, insn_addr, operand_idx):
        """
        Toggle the selection state of an operand of an instruction in the disassembly view.

        :param int insn_addr:   Address of the instruction to toggle.
        :param int operand_idx: The operand to toggle.
        :return:                None
        """

        if (insn_addr, operand_idx) in self.current_graph.selected_operands:
            self.current_graph.unselect_operand(insn_addr, operand_idx)
        else:
            self.current_graph.select_operand(insn_addr, operand_idx, unique=QApplication.keyboardModifiers() & Qt.CTRL == 0)
            self.current_graph.show_instruction(insn_addr)

    def jump_to(self, addr, src_ins_addr=None):

        # Record the current instruction address first
        if src_ins_addr is not None:
            self._jump_history.record_address(src_ins_addr)

        self._jump_history.jump_to(addr)
        self._jump_to(addr)

        return True

    def jump_back(self):
        addr = self._jump_history.backtrack()
        if addr is not None:
            self._jump_to(addr)

    def jump_forward(self):
        addr = self._jump_history.forwardstep()
        if addr is not None:
            self._jump_to(addr)

    def rename_label(self, addr, new_name):
        if self._flow_graph.disasm is not None:

            is_renaming = False

            kb = self._flow_graph.disasm.kb
            if new_name == '':
                if addr in kb.labels:
                    del kb.labels[addr]
            else:
                if addr in kb.labels:
                    is_renaming = True
                kb.labels[addr] = new_name

            # redraw the current block
            self._flow_graph.update_label(addr, is_renaming=is_renaming)

    def set_comment(self, addr, comment_text):
        if self._flow_graph.disasm is not None:

            is_updating = False

            kb = self._flow_graph.disasm.kb
            if comment_text is None and addr in kb.comments:
                del kb.comments[addr]
            else:
                is_updating = addr in kb.comments

            kb.comments[addr] = comment_text

            # redraw the current block
            self._flow_graph.update_comment(addr, comment_text)

    def avoid_addr_in_exec(self, addr):

        self.workspace.views_by_category['symexec'][0].avoid_addr_in_exec(addr)

    def sizeHint(self):
        return QSize(800, 800)

    def run_induction_variable_analysis(self):
        if self._flow_graph.induction_variable_analysis:
            self._flow_graph.induction_variable_analysis = None
        else:
            ana = self.workspace.instance.project.analyses.AffineRelationAnalysis(self._flow_graph._function_graph.function)
            self._flow_graph.induction_variable_analysis = ana
        self._flow_graph.refresh()

    #
    # Initialization
    #

    def _init_widgets(self):

        self._linear_viewer = QLinearViewer(self.workspace, self)
        self._flow_graph = QDisasmGraph(self.workspace, self)

        self._statusbar = QDisasmStatusBar(self, parent=self)

        hlayout = QVBoxLayout()
        hlayout.addWidget(self._flow_graph)
        hlayout.addWidget(self._linear_viewer)
        hlayout.addWidget(self._statusbar)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(hlayout)

        self.display_disasm_graph()
        # self.display_linear_viewer()

    def _init_menus(self):

        self._insn_menu = DisasmInsnContextMenu(self)

    #
    # Private methods
    #

    def _display_function(self, the_func):

        self._current_function = the_func

        # set status bar
        self._statusbar.function = the_func

        # variable recovery
        if self.workspace.instance.project.kb.variables.has_function_manager(the_func.addr):
            variable_manager = self.workspace.instance.project.kb.variables
        else:
            # run variable recovery analysis
            if self._variable_recovery_flavor == 'fast':
                vr = self.workspace.instance.project.analyses.VariableRecoveryFast(the_func)
            else:
                vr = self.workspace.instance.project.analyses.VariableRecovery(the_func)
            variable_manager = vr.variable_manager
        self.variable_manager = variable_manager
        self.infodock.variable_manager = variable_manager

        if self._flow_graph.isVisible():
            if self._flow_graph.function_graph is None or self._flow_graph.function_graph.function is not the_func:
                # clear existing selected instructions and operands
                self._flow_graph.selected_insns.clear()
                self._flow_graph.selected_operands.clear()
                # set function graph of a new function
                self._flow_graph.function_graph = FunctionGraph(function=the_func)
            else:
                # still use the current function. just unselect existing selections.
                self._flow_graph.unselect_all_instructions()
                self._flow_graph.unselect_all_operands()

            self.workspace.views_by_category['console'][0].push_namespace({
                'func': the_func,
                'function_': the_func,
            })

        elif self._linear_viewer.isVisible():
            self._linear_viewer.navigate_to_addr(the_func.addr)

    def _jump_to(self, addr):
        function = locate_function(self.workspace.instance, addr)
        if function is not None:
            self._display_function(function)
            self.toggle_instruction_selection(addr)
            return True
        else:
            return False

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
