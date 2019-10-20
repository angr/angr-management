import logging
from typing import Union, Callable

from PySide2.QtWidgets import QVBoxLayout, QMenu, QApplication
from PySide2.QtCore import Qt, QSize

from ...data.instance import ObjectContainer
from ...utils import locate_function
from ...data.function_graph import FunctionGraph
from ...logic.disassembly import JumpHistory, InfoDock
from ..widgets import QDisassemblyGraph, QDisasmStatusBar, QLinearDisassembly, QFeatureMap
from ..dialogs.jumpto import JumpTo
from ..dialogs.rename_label import RenameLabel
from ..dialogs.set_comment import SetComment
from ..dialogs.new_state import NewState
from ..dialogs.xref import XRef
from ..menus.disasm_insn_context_menu import DisasmInsnContextMenu
from .view import BaseView

_l = logging.getLogger(__name__)


class DisassemblyView(BaseView):
    def __init__(self, workspace, *args, **kwargs):
        super(DisassemblyView, self).__init__('disassembly', workspace, *args, **kwargs)

        self.caption = 'Disassembly'

        self._show_address = True
        self._show_variable = False #True
        # whether we want to show identifier or not
        self._show_variable_ident = False

        self._linear_viewer = None
        self._flow_graph = None  # type: QDisassemblyGraph
        self._statusbar = None
        self._jump_history = JumpHistory()
        self.infodock = InfoDock(self)
        self._variable_recovery_flavor = 'fast'
        self.variable_manager = None  # type: VariableManager
        self._current_function = ObjectContainer(None, 'The currently selected function')

        self._insn_menu = None  # type: DisasmInsnContextMenu

        self._insn_addr_on_context_menu = None

        # Callbacks
        self._insn_backcolor_callback = None  # type: Union[None, Callable[[int, bool], None]]   #  (addr, is_selected)
        self._label_rename_callback = None  # type: Union[None, Callable[[int, str], None]]      #  (addr, new_name)
        self._set_comment_callback = None  # type: Union[None, Callable[[int, str], None]]       #  (addr, comment_text)

        self._init_widgets()
        self._init_menus()
        self._register_events()

    def reload(self):

        self.infodock.initialize()
        self._feature_map.refresh()

        # Initialize the linear viewer
        # TODO: Relocate the logic to a better place
        self._linear_viewer.initialize()

    def refresh(self):
        self.current_graph.refresh()
        self._feature_map.refresh()

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
        """
        Return the current disassembly control, either linear viewer or flow graph.

        :return:    Linear viewer or flow graph.
        :rtype:     QLinearDisassembly or QDisassemblyGraph
        """
        if self._linear_viewer.isVisible():
            return self._linear_viewer
        else:
            return self._flow_graph

    #
    # Callbacks
    #

    @property
    def insn_backcolor_callback(self):
        return self._insn_backcolor_callback

    @insn_backcolor_callback.setter
    def insn_backcolor_callback(self, v):
        self._insn_backcolor_callback = v

    @property
    def label_rename_callback(self):
        return self._label_rename_callback

    @label_rename_callback.setter
    def label_rename_callback(self, v):
        self._label_rename_callback = v

    @property
    def set_comment_callback(self):
        return self._set_comment_callback

    @set_comment_callback.setter
    def set_comment_callback(self, v):
        self._set_comment_callback = v

    #
    # Events
    #

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_G:
            # jump to window
            self.popup_jumpto_dialog()
            return
        elif key == Qt.Key_Escape or (key == Qt.Key_Left and QApplication.keyboardModifiers() & Qt.ALT != 0):
            # jump back
            self.jump_back()
            return
        elif key == Qt.Key_Right and QApplication.keyboardModifiers() & Qt.ALT != 0:
            # jump forward
            self.jump_forward()
            return
        elif key == Qt.Key_A:
            # switch between highlight mode
            self.toggle_smart_highlighting(not self.infodock.smart_highlighting)
            return
        elif key == Qt.Key_Tab:
            # decompile
            self.decompile_current_function()
            return
        elif key == Qt.Key_Semicolon:
            # add comment
            self.popup_comment_dialog()
            return
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event):
        key = event.key()

        if key == Qt.Key_Space:
            # switch to linear view
            self.toggle_disasm_view()
            event.accept()
            return

        super().keyReleaseEvent(event)

    def _update_current_graph(self):
        """
        Redraw the graph currently in display.

        :return:    None
        """

        self.current_graph.redraw()

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

    def popup_xref_dialog(self, variable=None, dst_addr=None, asynch=True):

        if variable is not None:
            dialog = XRef(variable_manager=self.variable_manager, variable=variable, parent=self)
        else:
            dialog = XRef(xrefs_manager=self.workspace.instance.project.kb.xrefs, dst_addr=dst_addr, parent=self)
        if asynch:
            dialog.show()
        else:
            dialog.exec_()

    #
    # Public methods
    #

    def toggle_disasm_view(self):
        if self._flow_graph.isHidden():
            # Show flow graph
            self.display_disasm_graph()
        else:
            # Show linear viewer
            self.display_linear_viewer()

    def display_disasm_graph(self):

        self._linear_viewer.hide()
        self._flow_graph.show()

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self._flow_graph.show_instruction(next(iter(self.infodock.selected_insns)))
        elif self._current_function.am_obj is not None:
            self._flow_graph.show_instruction(self._current_function.addr)

        self._flow_graph.setFocus()

    def display_linear_viewer(self):

        self._flow_graph.hide()
        self._linear_viewer.show()

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self._linear_viewer.show_instruction(next(iter(self.infodock.selected_insns)))
        elif self._current_function.am_obj is not None:
            self._linear_viewer.show_instruction(self._current_function.addr)

        self._linear_viewer.setFocus()

    def display_function(self, function):

        self._jump_history.jump_to(function.addr)
        self._display_function(function)

    def decompile_current_function(self):

        if self._current_function.am_obj is not None:
            self.workspace.decompile_function(self._current_function.am_obj)

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

            # callback first
            if self._label_rename_callback:
                self._label_rename_callback(addr=addr, new_name=new_name)

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

            # callback first
            if self._set_comment_callback:
                self._set_comment_callback(addr=addr, comment_text=comment_text)

            # redraw
            self.current_graph.refresh()

    def avoid_addr_in_exec(self, addr):

        self.workspace.view_manager.first_view_in_category('symexec').avoid_addr_in_exec(addr)

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
        self._linear_viewer =  QLinearDisassembly(self.workspace, self, parent=self)
        self._flow_graph = QDisassemblyGraph(self.workspace, self, parent=self)
        self._feature_map = QFeatureMap(self, parent=self)

        self._statusbar = QDisasmStatusBar(self, parent=self)

        hlayout = QVBoxLayout()
        hlayout.addWidget(self._feature_map)
        hlayout.addWidget(self._flow_graph)
        hlayout.addWidget(self._linear_viewer)
        hlayout.addWidget(self._statusbar)
        hlayout.setContentsMargins(0, 0, 0, 0)

        self._feature_map.setMaximumHeight(25)
        hlayout.setStretchFactor(self._feature_map, 0)
        hlayout.setStretchFactor(self._flow_graph, 1)
        hlayout.setStretchFactor(self._linear_viewer, 1)
        hlayout.setStretchFactor(self._statusbar, 0)

        self.setLayout(hlayout)

        self.display_disasm_graph()
        # self.display_linear_viewer()

    def _init_menus(self):

        self._insn_menu = DisasmInsnContextMenu(self)

    def _register_events(self):

        # redraw the current graph if instruction/operand selection changes
        self.infodock.selected_insns.am_subscribe(self._update_current_graph)
        self.infodock.selected_operands.am_subscribe(self._update_current_graph)

        self._feature_map.addr.am_subscribe(lambda: self._jump_to(self._feature_map.addr.am_obj))

    #
    # Private methods
    #

    def _display_function(self, the_func):

        self._current_function.am_obj = the_func
        self._current_function.am_event()

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

        # clear existing selected instructions and operands
        self.infodock.clear_selection()

        if self._flow_graph.isVisible():
            if self._flow_graph.function_graph is None or self._flow_graph.function_graph.function is not the_func:
                # set function graph of a new function
                self._flow_graph.function_graph = FunctionGraph(function=the_func)

        elif self._linear_viewer.isVisible():
            self._linear_viewer.navigate_to_addr(the_func.addr)

        self.workspace.view_manager.first_view_in_category('console').push_namespace({
            'func': the_func,
            'function_': the_func,
        })

    def _jump_to(self, addr):
        function = locate_function(self.workspace.instance, addr)
        if function is not None:
            self._display_function(function)
            instr_addr = function.addr_to_instruction_addr(addr)
            if instr_addr is None:
                instr_addr = addr
            self.infodock.select_instruction(instr_addr, unique=True)
            return True
        else:
            return False

    #
    # Utils
    #

    def _address_in_selection(self):
        if self._insn_addr_on_context_menu is not None:
            return self._insn_addr_on_context_menu
        elif len(self.infodock.selected_insns) == 1:
            return next(iter(self.infodock.selected_insns))
        else:
            return None
