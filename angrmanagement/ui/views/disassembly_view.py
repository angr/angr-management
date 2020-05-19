import logging
from typing import Optional

from PySide2.QtWidgets import QHBoxLayout, QVBoxLayout, QMenu, QApplication
from PySide2.QtCore import Qt, QSize

from ...data.instance import ObjectContainer
from ...utils import locate_function
from ...data.function_graph import FunctionGraph
from ...logic.disassembly import JumpHistory, InfoDock
from ..widgets import QDisassemblyGraph, QDisasmStatusBar, QLinearDisassembly, QFeatureMap, QLinearDisassemblyView
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
        self._show_variable = True
        # whether we want to show identifier or not
        self._show_variable_ident = False
        # whether we want to show exception edges and all nodes that are only reachable through exception edges
        self._show_exception_edges = True

        self._linear_viewer = None  # type: Optional[QLinearDisassembly]
        self._flow_graph = None  # type: Optional[QDisassemblyGraph]
        self._statusbar = None
        self._jump_history = JumpHistory()
        self.infodock = InfoDock(self)
        self._variable_recovery_flavor = 'fast'
        self.variable_manager = None  # type: Optional[VariableManager]
        self._current_function = ObjectContainer(None, 'The currently selected function')

        self._insn_menu = None  # type: Optional[DisasmInsnContextMenu]

        self._insn_addr_on_context_menu = None

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
    def show_exception_edges(self):
        return self._show_exception_edges

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

    # All callbacks are proxies to self.workspace.instance. These properties *in this class* may be removed in the near
    # future.
    @property
    def insn_backcolor_callback(self):
        return self.workspace.instance.insn_backcolor_callback

    @insn_backcolor_callback.setter
    def insn_backcolor_callback(self, v):
        self.workspace.instance.insn_backcolor_callback = v

    @property
    def label_rename_callback(self):
        return self.workspace.instance.label_rename_callback

    @label_rename_callback.setter
    def label_rename_callback(self, v):
        self.workspace.instance.label_rename_callback = v

    @property
    def set_comment_callback(self):
        return self.workspace.instance.set_comment_callback

    @set_comment_callback.setter
    def set_comment_callback(self, v):
        self.workspace.instance.set_comment_callback = v

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

    def redraw_current_graph(self, **kwargs):
        """
        Redraw the graph currently in display.

        :return:    None
        """

        self.current_graph.redraw()

    def on_screen_changed(self):
        self.current_graph.refresh()

    #
    # UI
    #

    def instruction_context_menu(self, insn, pos):

        self._insn_addr_on_context_menu = insn.addr

        # pass in the instruction address
        self._insn_menu.insn_addr = insn.addr
        # pop up the menu
        self._insn_menu.qmenu(extra_entries=list(self.workspace.plugins.build_context_menu_insn(insn))).exec_(pos)

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

        dialog = SetComment(self.workspace, comment_addr, parent=self)
        dialog.exec_()

    def popup_newstate_dialog(self, async_=True):
        addr = self._address_in_selection()
        if addr is None:
            return

        dialog = NewState(self.workspace.instance, addr=addr, create_simgr=True, parent=self)
        if async_:
            dialog.show()
        else:
            dialog.exec_()

    def parse_operand_and_popup_xref_dialog(self, ins_addr, operand, async_=True):
        if operand is not None:
            if operand.variable is not None:
                # Display cross references to this variable
                self.popup_xref_dialog(addr=ins_addr, variable=operand.variable, async_=async_)
            elif operand.is_constant:
                # Display cross references to an address
                self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_value, async_=async_)
            elif operand.is_constant_memory:
                # Display cross references to an address
                self.popup_xref_dialog(addr=ins_addr, dst_addr=operand.constant_memory_value, async_=async_)

    def popup_xref_dialog(self, addr=None, variable=None, dst_addr=None, async_=True):

        if variable is not None:
            dialog = XRef(addr=addr, variable_manager=self.variable_manager, variable=variable,
                          instance=self.workspace.instance, parent=self)
        else:
            dialog = XRef(addr=addr, xrefs_manager=self.workspace.instance.project.kb.xrefs, dst_addr=dst_addr,
                          instance=self.workspace.instance, parent=self)
        if async_:
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
            self._jump_to(next(iter(self.infodock.selected_insns)))
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

    def toggle_show_exception_edges(self, show_exception_edges):
        """
        Toggle whether exception edges and the nodes that are only reachable through exception edges should be shown
        or not.

        :param bool show_exception_edges:   Whether exception edges should be shown or not.
        :return:                            None
        """

        if show_exception_edges != self._show_exception_edges:
            self._show_exception_edges = show_exception_edges

            # reset the function graph
            if self._flow_graph.function_graph is not None:
                self._flow_graph.function_graph.exception_edges = show_exception_edges
                self._flow_graph.function_graph.clear_cache()
                self._flow_graph.reload()

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

    def select_label(self, label_addr):
        self.infodock.select_label(label_addr)

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
            if self.workspace.instance.label_rename_callback:
                self.workspace.instance.label_rename_callback(addr=addr, new_name=new_name)

            # redraw the current block
            self._flow_graph.update_label(addr, is_renaming=is_renaming)

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
        self._linear_viewer = QLinearDisassembly(self.workspace, self, parent=self)
        self._flow_graph = QDisassemblyGraph(self.workspace, self, parent=self)
        self._feature_map = QFeatureMap(self, parent=self)
        self._statusbar = QDisasmStatusBar(self, parent=self)

        vlayout = QVBoxLayout()
        vlayout.addWidget(self._feature_map)
        vlayout.addWidget(self._flow_graph)
        vlayout.addWidget(self._linear_viewer)
        vlayout.addWidget(self._statusbar)
        vlayout.setContentsMargins(0, 0, 0, 0)

        self._feature_map.setMaximumHeight(25)
        vlayout.setStretchFactor(self._feature_map, 0)
        vlayout.setStretchFactor(self._flow_graph, 1)
        vlayout.setStretchFactor(self._linear_viewer, 1)
        vlayout.setStretchFactor(self._statusbar, 0)

        hlayout = QHBoxLayout()
        hlayout.addLayout(vlayout)

        self.setLayout(hlayout)

        self.display_disasm_graph()
        # self.display_linear_viewer()

        self.workspace.plugins.instrument_disassembly_view(self)

    def _init_menus(self):
        self._insn_menu = DisasmInsnContextMenu(self)

    def _register_events(self):
        # redraw the current graph if instruction/operand selection changes
        self.infodock.selected_insns.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_operands.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_blocks.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_block.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_edge.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_labels.am_subscribe(self.redraw_current_graph)

        self._feature_map.addr.am_subscribe(lambda: self._jump_to(self._feature_map.addr.am_obj))

        self.workspace.current_screen.am_subscribe(self.on_screen_changed)

    #
    # Private methods
    #

    def _display_function(self, the_func):
        self._current_function.am_obj = the_func
        self._current_function.am_event()

        # set status bar
        self._statusbar.function = the_func

        # variable recovery
        variable_manager = self.workspace.instance.project.kb.variables
        self.variable_manager = variable_manager
        self.infodock.variable_manager = variable_manager

        # clear existing selected instructions and operands
        self.infodock.clear_selection()

        if self._flow_graph.isVisible():
            if self._flow_graph.function_graph is None or self._flow_graph.function_graph.function is not the_func:
                # set function graph of a new function
                self._flow_graph.function_graph = FunctionGraph(function=the_func,
                                                                exception_edges=self.show_exception_edges,
                                                                )

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

        # it does not belong to any function - we need to switch to linear view mode
        if self.current_graph is not self._linear_viewer:
            self.display_linear_viewer()
        self._linear_viewer.navigate_to_addr(addr)
        return True

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
