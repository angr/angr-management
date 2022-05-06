
from collections import defaultdict
import logging
from typing import Union, Optional, TYPE_CHECKING

import PySide2
from PySide2.QtWidgets import QHBoxLayout, QVBoxLayout, QApplication, QMessageBox, QMenu, QAction
from PySide2.QtCore import Qt, Signal
from PySide2.QtGui import QCursor
from angr.block import Block
from angr.knowledge_plugins.cfg import MemoryData

from ...logic import GlobalInfo
from ...data.instance import ObjectContainer
from ...utils import locate_function
from ...data.function_graph import FunctionGraph
from ...data.highlight_region import SynchronizedHighlightRegion
from ...logic.disassembly import JumpHistory, InfoDock
from ..widgets import QDisassemblyGraph, QDisasmStatusBar, QLinearDisassembly, QFeatureMap,\
    QLinearDisassemblyView, DisassemblyLevel
from ..dialogs.dependson import DependsOn
from ..dialogs.jumpto import JumpTo
from ..dialogs.rename import RenameDialog
from ..dialogs.rename_label import RenameLabel
from ..dialogs.set_comment import SetComment
from ..dialogs.new_state import NewState
from ..dialogs.xref import XRef
from ..dialogs.hook import HookDialog
from ..dialogs.func_doc import FuncDocDialog
from ..menus.disasm_insn_context_menu import DisasmInsnContextMenu
from ..menus.disasm_label_context_menu import DisasmLabelContextMenu
from .view import SynchronizedView
from ..widgets import QFindAddrAnnotation, QAvoidAddrAnnotation, QBlockAnnotations
from ..widgets.qblock_code import QVariableObj
from ...ui.widgets.qinst_annotation import QHookAnnotation, QBreakAnnotation

if TYPE_CHECKING:
    from angr.knowledge_plugins import VariableManager


_l = logging.getLogger(__name__)


class DisassemblyView(SynchronizedView):
    """
    Disassembly View
    """

    FUNCTION_SPECIFIC_VIEW = True

    view_visibility_changed = Signal()
    disassembly_level_changed = Signal(DisassemblyLevel)

    def __init__(self, workspace, *args, **kwargs):
        super().__init__('disassembly', workspace, *args, **kwargs)

        self.base_caption = 'Disassembly'
        self._disassembly_level = DisassemblyLevel.MachineCode
        self._show_minimap: bool = True
        self._show_address = True
        self._show_variable = True
        # whether we want to show identifier or not
        self._show_variable_ident = False
        # whether we want to show exception edges and all nodes that are only reachable through exception edges
        self._show_exception_edges = True

        self._linear_viewer = None  # type: Optional[QLinearDisassembly]
        self._flow_graph = None  # type: Optional[QDisassemblyGraph]
        self._prefer_graph = True
        self._statusbar = None
        self.jump_history: JumpHistory = JumpHistory()
        self.infodock = InfoDock(self)
        self._variable_recovery_flavor = 'fast'
        self.variable_manager = None  # type: Optional[VariableManager]
        self._current_function = ObjectContainer(None, 'The currently selected function')

        # For tests only
        self._t_linear_viewer_visible: bool = False
        self._t_flow_graph_visible: bool = False

        self._insn_menu = None  # type: Optional[DisasmInsnContextMenu]
        self._label_menu = None  # type: Optional[DisasmLabelContextMenu]

        self._insn_addr_on_context_menu = None
        self._label_addr_on_context_menu = None

        self._annotation_callbacks = []

        self.width_hint = 800
        self.height_hint = 800

        self._init_widgets()
        self._init_menus()
        self._register_events()

    @property
    def disassembly_level(self):
        return self._disassembly_level

    def set_disassembly_level(self, level:DisassemblyLevel):
        self._disassembly_level = level
        self._flow_graph.set_disassembly_level(level)
        self._linear_viewer.set_disassembly_level(level)
        self.disassembly_level_changed.emit(level)
        self.redraw_current_graph()

    def reload(self):

        old_infodock = self.infodock.copy()

        self.infodock.initialize()
        self._feature_map.refresh()

        # Reload the current graph to make sure it gets the latest information, such as variables.
        self.current_graph.reload(old_infodock=old_infodock)

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
    def show_minimap(self):
        return self._show_minimap

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
    def current_graph(self) -> Union[QLinearDisassemblyView,QDisassemblyGraph]:
        """
        Return the current disassembly control, either linear viewer or flow graph.

        :return:    Linear viewer or flow graph.
        """
        if self._linear_viewer.isVisible() or self._t_linear_viewer_visible:
            return self._linear_viewer
        else:
            return self._flow_graph

    @property
    def current_function(self) -> ObjectContainer:
        return self._current_function

    @property
    def function(self) -> ObjectContainer:
        return self._current_function

    @function.setter
    def function(self, v):
        if v is not self._current_function.am_obj:
            self.display_function(v)

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

    def on_variable_recovered(self, func_addr: int):
        if not self._current_function.am_none and self._current_function.addr == func_addr:
            self.reload()

    #
    # Events
    #

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_G:
            # jump to window
            self.popup_jumpto_dialog()
            return
        elif key == Qt.Key_Left and QApplication.keyboardModifiers() & Qt.ALT != 0:
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
        elif key == Qt.Key_Space:
            # switch to linear view
            self.toggle_disasm_view()
            event.accept()
            return
        elif key == Qt.Key_Escape:
            # jump back
            self.jump_back()
            return

        super().keyPressEvent(event)

    def redraw_current_graph(self, **kwargs):  # pylint: disable=unused-argument
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

    def append_view_menu_actions(self, menu: QMenu):
        """
        Append a separator and general QActions for this view to a given context menu.
        """
        menu.addSeparator()
        menu.addMenu(self.get_synchronize_with_submenu())

    def contextMenuEvent(self, event: PySide2.QtGui.QContextMenuEvent):  # pylint: disable=unused-argument
        """
        Display view context menu.
        """
        mnu = QMenu(self)
        mnu.addMenu(self.get_synchronize_with_submenu())
        mnu.exec_(QCursor.pos())

    def instruction_context_menu(self, insn, pos):

        self._insn_addr_on_context_menu = insn.addr

        # pass in the instruction address
        self._insn_menu.insn_addr = insn.addr
        # pop up the menu
        mnu = self._insn_menu.qmenu(extra_entries=list(self.workspace.plugins.build_context_menu_insn(insn)),
                                    cached=False)
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)

        self._insn_addr_on_context_menu = None

    def label_context_menu(self, addr: int, pos):

        self._label_addr_on_context_menu = addr
        self._label_menu.addr = addr
        mnu = self._label_menu.qmenu(cached=False)
        self.append_view_menu_actions(mnu)
        mnu.exec_(pos)
        self._label_addr_on_context_menu = None

    def rename_selected_object(self):
        """
        Opens dialog for renaming the currently selected QBlockCodeObj
        """
        obj = self.infodock.selected_qblock_code_obj
        if isinstance(obj, QVariableObj):
            dlg = RenameDialog('Rename Variable', obj.obj.name, self)
            dlg.exec_()
            if dlg.result is not None:
                obj.obj.name = dlg.result
                self.current_graph.refresh()

    def get_context_menu_for_selected_object(self) -> Optional[QMenu]:
        """
        Returns a QMenu object for the currently selected QBlockCodeObj
        """
        obj = self.infodock.selected_qblock_code_obj
        if isinstance(obj, QVariableObj):
            rename_act = QAction('Re&name', self)
            rename_act.triggered.connect(self.rename_selected_object)
            mnu = QMenu()
            mnu.addActions([rename_act])
            return mnu
        else:
            return None

    def show_context_menu_for_selected_object(self):
        """
        Spawns a context menu for the currently selected QBlockCodeObj
        """
        mnu = self.get_context_menu_for_selected_object()
        if mnu is not None:
            self.append_view_menu_actions(mnu)
            mnu.exec_(QCursor.pos())

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

    def popup_hook_dialog(self, async_=True, addr=None):
        addr = addr or self._address_in_selection()

        if addr is None:
            return

        dialog = HookDialog(self.workspace.instance, addr=addr, parent=self)
        if async_:
            dialog.show()
        else:
            dialog.exec_()

    def popup_func_doc_dialog(self, instr_addr):
        """
        Spawns a popup dialog for the currently selected call instruction func_docs
        """
        if self._flow_graph is None:
            return
        block = self._flow_graph._insaddr_to_block.get(instr_addr, None)
        if block:
            instr = block.addr_to_insns[instr_addr]
            if instr is None or instr.insn.type != "call":
                return
            out_targets = instr.out_branch.targets
            if len(out_targets) != 1:
                return

            target = next(iter(out_targets))
            operand = instr.get_operand(0)

            doc_tuple = GlobalInfo.library_docs.get_docstring_for_func_name(operand.text)
            if doc_tuple is None:
                doc_string = f"Cannot find local documentation for function {operand.text}."
                url = "http://"
                ftype = "<>"
                doc_tuple = (doc_string, url, ftype)
            dialog = FuncDocDialog(self.workspace.instance,
                                   addr=target, name=operand.text, doc_tuple=doc_tuple,
                                   parent=self)
            dialog.show()

    def popup_dependson_dialog(self, addr: Optional[int]=None, use_operand=False, func: bool=False):
        if use_operand:
            r = self._flow_graph.get_selected_operand_info()
            if r is not None:
                _, addr, operand = r
            else:
                QMessageBox.critical(self,
                                     "No operand",
                                     "Please select an operand first.",
                                     buttons=QMessageBox.Ok,
                                     )
                return
        else:
            if addr is None:
                raise ValueError("No address is provided.")  # this is a programming error
            operand = None

        # if a function target is selected, switch to function mode
        if operand is not None and not func:
            if operand._branch_target is not None and operand._is_target_func:
                func = True
                addr = operand._branch_target

        if func:
            # attempt to pass in a function
            try:
                the_func = self.workspace.instance.kb.functions.get_by_addr(addr)
            except KeyError:
                the_func = None
        else:
            the_func = None

        dependson = DependsOn(addr, operand, func=the_func, parent=self)
        dependson.exec_()

        if dependson.location is not None:
            if dependson.arg is not None:
                # track function argument
                self.workspace._main_window.run_dependency_analysis(
                    func_addr=addr,
                    func_arg_idx=dependson.arg,
                )

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

    def toggle_disasm_view(self, prefer=True):
        if self._flow_graph.isHidden():
            # Show flow graph
            self.display_disasm_graph(prefer)
        else:
            # Show linear viewer
            self.display_linear_viewer(prefer)

    def display_disasm_graph(self, prefer=True):
        if prefer:
            self._prefer_graph = True

        self._linear_viewer.hide()
        self._flow_graph.show()

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self._jump_to(next(iter(self.infodock.selected_insns)))
        elif self._current_function.am_obj is not None:
            self._flow_graph.show_instruction(self._current_function.addr)

        self._flow_graph.setFocus()
        self.view_visibility_changed.emit()
        self._flow_graph.refresh()

    def display_linear_viewer(self, prefer=True):
        if prefer:
            self._prefer_graph = False

        self._flow_graph.hide()
        self._linear_viewer.show()

        if self.infodock.selected_insns:
            # display the currently selected instruction
            self._linear_viewer.show_instruction(next(iter(self.infodock.selected_insns)))
        elif self._current_function.am_obj is not None:
            self._linear_viewer.show_instruction(self._current_function.addr)

        self._linear_viewer.setFocus()
        self.view_visibility_changed.emit()
        self._linear_viewer.refresh()

    def display_function(self, function):
        if function.addr not in self.workspace.instance.kb.variables.function_managers:
            # variable information is not available
            if self.workspace.variable_recovery_job is not None:
                # prioritize the analysis of this function
                self.workspace.variable_recovery_job.prioritize_function(function.addr)
        self.jump_history.jump_to(function.addr)
        self._display_function(function)

    def decompile_current_function(self):

        if self._current_function.am_obj is not None:
            try:
                curr_ins = next(iter(self.infodock.selected_insns))
            except StopIteration:
                curr_ins = None

            self.workspace.decompile_function(self._current_function.am_obj, curr_ins=curr_ins)

    def toggle_show_minimap(self, show:bool):
        """
        Toggle minimap display preference
        """
        self._show_minimap = show
        self.current_graph.refresh()

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

    def jump_to(self, addr, src_ins_addr=None, use_animation=False):

        # Record the current instruction address first
        if src_ins_addr is not None:
            self.jump_history.record_address(src_ins_addr)

        self.jump_history.jump_to(addr)
        self._jump_to(addr, use_animation=use_animation)

        return True

    def jump_back(self):
        addr = self.jump_history.backtrack()
        if addr is not None:
            self._jump_to(addr, use_animation=False)

    def jump_forward(self):
        addr = self.jump_history.forwardstep()
        if addr is not None:
            self._jump_to(addr, use_animation=False)

    def jump_to_history_position(self, pos:int):
        addr = self.jump_history.step_position(pos)
        if addr is not None:
            self._jump_to(addr, use_animation=False)

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
        self.workspace._get_or_create_symexec_view().avoid_addr_in_exec(addr)

    def find_addr_in_exec(self, addr):
        self.workspace._get_or_create_symexec_view().find_addr_in_exec(addr)

    def run_induction_variable_analysis(self):
        if self._flow_graph.induction_variable_analysis:
            self._flow_graph.induction_variable_analysis = None
        else:
            analyses = self.workspace.instance.project.analyses
            ana = analyses.AffineRelationAnalysis(self._flow_graph._function_graph.function)
            self._flow_graph.induction_variable_analysis = ana
        self._flow_graph.refresh()

    def fetch_qblock_annotations(self, qblock):
        addr_to_annotations = defaultdict(list)
        for annotations in self.workspace.plugins.build_qblock_annotations(qblock):
            addr_to_annotations[annotations.addr].append(annotations)
        for addr in qblock.addr_to_insns.keys():
            if addr in self.workspace.instance.project._sim_procedures:
                hook_annotation = QHookAnnotation(addr)
                addr_to_annotations[addr].append(hook_annotation)
            view = self.workspace.view_manager.first_view_in_category("symexec")
            if view is not None:
                qsimgrs = view._simgrs
                if addr in qsimgrs.find_addrs:
                    addr_to_annotations[addr].append(QFindAddrAnnotation(addr, qsimgrs))
                if addr in qsimgrs.avoid_addrs:
                    addr_to_annotations[addr].append(QAvoidAddrAnnotation(addr, qsimgrs))
                for bp in self.workspace.instance.breakpoint_mgr.get_breakpoints_at(addr):
                    addr_to_annotations[addr].append(QBreakAnnotation(bp))

        return QBlockAnnotations(addr_to_annotations, parent=qblock, disasm_view=self)

    def update_highlight_regions_for_synchronized_views(self, **kwargs):  # pylint: disable=unused-argument
        """
        Highlight each selected instruction in synchronized views.
        """
        regions = []
        for addr in self.infodock.selected_insns:
            s = self._get_instruction_size(addr)
            if s is not None:
                regions.append(SynchronizedHighlightRegion(addr, s))
        self.set_synchronized_highlight_regions(regions)

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
        self._label_menu = DisasmLabelContextMenu(self)

    def _register_events(self):
        # redraw the current graph if instruction/operand selection changes
        self.infodock.selected_insns.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_insns.am_subscribe(self.update_highlight_regions_for_synchronized_views)
        self.infodock.selected_operands.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_blocks.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_block.am_subscribe(self.redraw_current_graph)
        self.infodock.hovered_edge.am_subscribe(self.redraw_current_graph)
        self.infodock.selected_labels.am_subscribe(self.redraw_current_graph)
        self.infodock.qblock_code_obj_selection_changed.connect(self.redraw_current_graph)
        self._feature_map.addr.am_subscribe(lambda: self._jump_to(self._feature_map.addr.am_obj))
        self.workspace.current_screen.am_subscribe(self.on_screen_changed)
        self.workspace.instance.breakpoint_mgr.breakpoints.am_subscribe(lambda **kwargs: self.refresh())

    #
    # Private methods
    #

    def _display_function(self, the_func):
        self.set_synchronized_cursor_address(the_func.addr)

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

        if self._flow_graph.isVisible() or self._t_flow_graph_visible:
            if self._flow_graph.function_graph is None or self._flow_graph.function_graph.function is not the_func:
                # set function graph of a new function
                self._flow_graph.function_graph = FunctionGraph(function=the_func,
                                                                exception_edges=self.show_exception_edges,
                                                                )

        elif self._linear_viewer.isVisible() or self._t_linear_viewer_visible:
            self._linear_viewer.navigate_to_addr(the_func.addr)

        view = self.workspace.view_manager.first_view_in_category('console')
        if view is not None:
            view.push_namespace({
                'func': the_func,
                'function_': the_func,
            })

    def _jump_to(self, addr, use_animation=False):
        if self._prefer_graph and self.current_graph is self._linear_viewer:
            self.display_disasm_graph(prefer=False)

        if self.current_graph is not self._linear_viewer:
            function = locate_function(self.workspace.instance, addr)
            if function is not None:
                self._display_function(function)
                instr_addr = function.addr_to_instruction_addr(addr)
                if instr_addr is None:
                    instr_addr = addr
                self.infodock.select_instruction(instr_addr, unique=True, use_animation=use_animation)
                return True

            # it does not belong to any function - we need to switch to linear view mode
            self.display_linear_viewer(prefer=False)

        try:
            item = self.workspace.instance.cfb.floor_item(addr)
            _, item = item
            if isinstance(item, MemoryData) and addr < (item.addr + item.size):
                self.infodock.select_label(item.addr)
            elif isinstance(item, Block) and item.size and addr < (item.addr + item.size):
                addr = max(a for a in item.instruction_addrs if a <= addr)
                self.infodock.select_instruction(addr, unique=True, use_animation=use_animation)
                return True  # select_instruction will navigate
        except KeyError:
            pass

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
        elif len(self.infodock.selected_labels) == 1:
            return next(iter(self.infodock.selected_labels))
        else:
            return None

    def _get_instruction_size(self, addr: int) -> Optional[int]:
        kb = self.workspace.instance.project.kb
        f = kb.functions.floor_func(addr)
        if f is None:
            return None
        return f.instruction_size(addr)
