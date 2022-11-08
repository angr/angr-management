import os
from typing import TYPE_CHECKING, Callable, Optional, List, Union
import logging
import traceback
import time

from PySide6.QtWidgets import QMessageBox
from angr.knowledge_plugins.functions.function import Function
from angr import StateHierarchy
from angr.misc.testing import is_testing
from cle import SymbolType

from ..logic.debugger import DebuggerWatcher
from ..logic.debugger.bintrace import BintraceDebugger

from ..config import Conf
from ..data.breakpoint import Breakpoint, BreakpointType
from ..data.trace import BintraceTrace, Trace
from ..data.instance import ObjectContainer
from ..data.jobs.loading import LoadBinaryJob
from ..data.jobs import CodeTaggingJob, PrototypeFindingJob, VariableRecoveryJob, FlirtSignatureRecognitionJob, \
    CFGGenerationJob
from ..data.analysis_options import AnalysesConfiguration, CFGAnalysisConfiguration, FlirtAnalysisConfiguration, \
    VariableRecoveryConfiguration
from .views import (FunctionsView, DisassemblyView, SymexecView, StatesView, StringsView, ConsoleView, CodeView,
                    InteractionView, PatchesView, DependencyView, ProximityView, TypesView, HexView, LogView,
                    DataDepView, RegistersView, StackView, TracesView, TraceMapView, BreakpointsView,
                    CallExplorerView)
from .view_manager import ViewManager
from .menus.disasm_insn_context_menu import DisasmInsnContextMenu
from .dialogs import AnalysisOptionsDialog
from ..logic.threads import gui_thread_schedule_async

from ..plugins import PluginManager

if TYPE_CHECKING:
    from ..data.instance import Instance
    from angrmanagement.ui.main_window import MainWindow


_l = logging.getLogger(__name__)


class Workspace:
    """
    This class implements the angr management workspace.
    """
    def __init__(self, main_window, instance):

        self.main_window: 'MainWindow' = main_window
        self._main_instance = instance
        instance.workspace = self

        self.view_manager: ViewManager = ViewManager(self)
        self.plugins: PluginManager = PluginManager(self)
        self.variable_recovery_job: Optional[VariableRecoveryJob] = None

        self.current_screen = ObjectContainer(None, name="current_screen")

        self.default_tabs = [
            DisassemblyView(self._main_instance, 'center'),
            HexView(self._main_instance, 'center'),
            ProximityView(self._main_instance, 'center'),
            CodeView(self._main_instance, 'center'),
            FunctionsView(self._main_instance, 'left'),
        ]
        if Conf.has_operation_mango:
            self.default_tabs.append(
                DependencyView(self._main_instance, 'center')
            )
        self.default_tabs += [
            StringsView(self._main_instance, 'center'),
            PatchesView(self._main_instance, 'center'),
            SymexecView(self._main_instance, 'center'),
            StatesView(self._main_instance, 'center'),
            InteractionView(self._main_instance, 'center'),
            ConsoleView(self._main_instance, 'bottom'),
            LogView(self._main_instance, 'bottom'),
        ]

        enabled_tabs = [x.strip() for x in Conf.enabled_tabs.split(",") if x.strip()]
        for tab in self.default_tabs:
            if tab.__class__.__name__ in enabled_tabs or len(enabled_tabs)==0:
                self.add_view(tab)

        self._dbg_watcher = DebuggerWatcher(self.on_debugger_state_updated, self.main_instance.debugger_mgr.debugger)
        self.on_debugger_state_updated()

        self._analysis_configuration: Optional[AnalysesConfiguration] = None

    #
    # Properties
    #

    @property
    def _main_window(self) -> 'MainWindow':
        return self.main_window

    @property
    def main_instance(self) -> 'Instance':
        return self._main_instance

    #
    # Events
    #

    def on_debugger_state_updated(self):
        """
        Jump to debugger target PC in active disassembly view.
        """
        # FIXME: the disassembly view should subscribe to debugger updates, but for that we will need to expose
        #        a mechanism for the view to select between states. For now we simply have a global debugger
        #        selection.
        dbg = self._dbg_watcher.debugger
        if not dbg.am_none:
            state = dbg.simstate
            if state is not None:
                addr = state.solver.eval(state.regs.pc)
                view = self.view_manager.current_view_in_category('disassembly') or \
                       self.view_manager.first_view_in_category('disassembly')
                if view:
                    view.jump_to(addr, True)

    def on_function_selected(self, func: Function):
        self.main_instance.on_function_selected(func)

    def on_function_tagged(self):
        self.main_instance.on_function_tagged()

    def on_variable_recovered(self, func_addr: int):
        self.main_instance.on_variable_recovered(func_addr)

    #
    # Public methods
    #

    def new_disassembly_view(self) -> DisassemblyView:
        """
        Add a new disassembly view.
        """
        disassembly_view = self.view_manager.first_view_in_category("disassembly")
        if disassembly_view is not None:
            current_addr = disassembly_view.jump_history.current
        else:
            current_addr = None

        view = DisassemblyView(self._main_instance, 'center')
        self.add_view(view)
        self.raise_view(view)
        view._linear_viewer.initialize()  # FIXME: Don't access protected member
        if current_addr is not None:
            view.jump_to(current_addr)
        # TODO move view tab to front of dock
        return view

    def add_view(self, view):
        self.view_manager.add_view(view)

    def remove_view(self, view):
        self.view_manager.remove_view(view)

    def raise_view(self, view):
        """
        Find the dock widget of a view, and then bring that dockable to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        self.view_manager.raise_view(view)

    def reload(self, categories: Optional[List[str]]=None):
        """
        Ask all or specified views to reload the underlying data and regenerate the UI. This is usually expensive.

        :param categories:  Specify a list of view categories that should be reloaded.
        :return:            None
        """

        if categories is None:
            views = self.view_manager.views
        else:
            views = [ ]
            for category in categories:
                views.extend(self.view_manager.views_by_category.get(category, [ ]))

        for view in views:
            try:
                view.reload()
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

    def refresh(self, categories: Optional[List[str]]=None):
        """
        Ask all or specified views to refresh based on changes in the underlying data and refresh the UI if needed. This
        may be called frequently so it must be extremely fast.

        :param categories:  Specify a list of view categories that should be reloaded.
        :return:            None
        """

        if categories is None:
            views = self.view_manager.views
        else:
            views = [ ]
            for category in categories:
                views.extend(self.view_manager.views_by_category.get(category, [ ]))

        for view in views:
            try:
                view.refresh()
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

    def viz(self, obj):
        """
        Visualize the given object.

        - For integers, open the disassembly view and jump to that address
        - For Function objects, open the disassembly view and jump there
        - For strings, look up the symbol of that name and jump there
        """

        if type(obj) is int:
            self.jump_to(obj)
        elif type(obj) is str:
            sym = self.main_instance.project.loader.find_symbol(obj)
            if sym is not None:
                self.jump_to(sym.rebased_addr)
        elif type(obj) is Function:
            self.jump_to(obj.addr)

    def jump_to(self, addr, view=None, use_animation=False):
        if view is None or view.category != 'disassembly':
            view = self._get_or_create_disassembly_view()

        view.jump_to(addr, use_animation=use_animation)
        self.raise_view(view)
        view.setFocus()

    def add_breakpoint(self, obj: Union[str, int], type_: Optional[str] = None, size: Optional[int] = None):
        """
        Convenience function to add a breakpoint.

        Examples:
        - `workspace.add_breakpoint(0x1234)` sets an execution breakpoint on address 0x1234
        - `workspace.add_breakpoint('main')` sets an execution breakpoint on `main` function
        - `workspace.add_breakpoint('global_value')` sets a write breakpoint on `global_value`
        - `workspace.add_breakpoint('global_value', 'read', 1)` sets a 1-byte read breakpoint on `global_value`
        """
        if type(obj) is int:
            addr = obj
        elif type(obj) is str:
            sym = self.main_instance.project.loader.find_symbol(obj)
            if sym is None:
                _l.error("Couldn't resolve '%s'", obj)
                return
            addr = sym.rebased_addr
            if not size:
                size = sym.size
            if not type_:
                if sym.type == SymbolType.TYPE_FUNCTION:
                    type_ = 'execute'
                else:
                    type_ = 'write'
        elif type(obj) is Function:
            addr = obj.addr
            if not type_:
                type_ = 'execute'
        else:
            _l.error('Unexpected target object type. Expected int | str | Function')
            return

        if not size:
            size = 1

        bp_type_map = {
            None: BreakpointType.Execute,
            'execute': BreakpointType.Execute,
            'write': BreakpointType.Write,
            'read': BreakpointType.Read,
        }
        if type_ not in bp_type_map:
            _l.error("Unknown breakpoint type '%s'. Expected %s",
                     type_, ' | '.join(bp_type_map.keys()))
            return

        bp = Breakpoint(bp_type_map[type_], addr, size)
        self.main_instance.breakpoint_mgr.add_breakpoint(bp)

    def set_comment(self, addr, comment_text):
        self.main_instance.set_comment(addr, comment_text)

        disasm_view = self._get_or_create_disassembly_view()
        if disasm_view._flow_graph.disasm is not None:
            # redraw
            disasm_view.current_graph.refresh()

    def run_analysis(self, prompt_for_configuration=True):
        self.main_instance.run_analysis(prompt_for_configuration=prompt_for_configuration)

    def decompile_current_function(self):
        current = self.view_manager.current_tab
        if isinstance(current, CodeView):
            current.decompile()
        else:
            view = self._get_or_create_disassembly_view()
            view.decompile_current_function()

    def view_data_dependency_graph(self, analysis_params: dict):
        view = self._get_or_create_data_dependency_graph(analysis_params)
        self.raise_view(view)

    def view_proximity_for_current_function(self, view=None):
        if view is None or view.category != "proximity":
            view = self._get_or_create_proximity_view()

        disasm_view = self._get_or_create_disassembly_view()
        if disasm_view.current_function is not None:
            view.function = disasm_view.current_function.am_obj

        self.raise_view(view)

    def decompile_function(self, func: Function, curr_ins=None, view=None):
        """
        Decompile a function a switch to decompiled view. If curr_ins is
        defined, then also switch cursor focus to the position associated
        with the asm instruction addr

        :param func: The function to decompile
        :param curr_ins: The instruction the cursor was at before switching to decompiled view
        :param view: The decompiled qt text view
        :return:
        """

        if view is None or view.category != "pseudocode":
            view = self._get_or_create_pseudocode_view()

        view.function.am_obj = func
        view.function.am_event(focus=True, focus_addr=curr_ins)

    def create_simulation_manager(self, state, state_name, view=None):

        inst = self.main_instance
        hierarchy = StateHierarchy()
        simgr = inst.project.factory.simulation_manager(state, hierarchy=hierarchy)
        simgr_container = ObjectContainer(simgr, name=state_name)
        inst.simgrs.append(simgr_container)
        inst.simgrs.am_event(src='new_path')

        if view is None:
            view = self._get_or_create_symexec_view()
        view.select_simgr(simgr_container)

        self.raise_view(view)

    def create_trace_debugger(self):
        if self.main_instance.current_trace.am_none:
            _l.error('No trace available')
            return

        if isinstance(self.main_instance.current_trace.am_obj, BintraceTrace):
            dbg = BintraceDebugger(self.main_instance.current_trace.am_obj, self)
            dbg.init()
            self.main_instance.debugger_list_mgr.add_debugger(dbg)
            self.main_instance.debugger_mgr.set_debugger(dbg)

    def is_current_trace(self, trace: Optional[Trace]) -> bool:
        return self.main_instance.current_trace.am_obj is trace

    def set_current_trace(self, trace: Optional[Trace]):
        self.main_instance.current_trace.am_obj = trace
        self.main_instance.current_trace.am_event()

    def remove_trace(self, trace: Trace):
        if self.is_current_trace(trace):
            self.set_current_trace(None)
        self.main_instance.traces.remove(trace)
        self.main_instance.traces.am_event(trace_removed=trace)
        # Note: Debuggers and other objects may retain trace

    def load_trace_from_path(self, path: str):
        if not BintraceTrace.trace_backend_enabled():
            QMessageBox.critical(None, "Error", "bintrace is not installed. Please install the bintrace package.")
            return

        _l.info("Opening trace %s", path)
        trace = BintraceTrace.load_trace(path)

        def on_complete():
            if not self.main_instance.project.am_none:
                self.main_instance.traces.append(trace)
                self.main_instance.traces.am_event(trace_added=trace)
                self.main_instance.current_trace.am_obj = trace
                self.main_instance.current_trace.am_event()
                self.show_traces_view()

        if self.main_instance.project.am_none:
            QMessageBox.information(None, "Creating project", "Creating new project from trace.")
            self.create_project_from_trace(trace, on_complete)
        else:
            on_complete()

    def create_project_from_trace(self, trace: Trace, on_complete: Callable):
        thing = None
        load_options = trace.get_project_load_options()

        if load_options is None:
            QMessageBox.warning(None, "Error", "Failed to determine load options for binary from trace. "
                                      "Please select binary.")
            load_options = {}
        else:
            thing = load_options["thing"]
            load_options = load_options["load_options"]
            if not os.path.exists(thing):
                QMessageBox.warning(None, "Unable to find target binary!",
                                          f"Unable to find the traced binary at: \n\n{thing}\n\n"
                                          "Please select target binary.")
                thing = None

        if not thing:
            thing = self.main_window.open_mainfile_dialog()

        if not thing:
            on_complete()
            return

        self.main_instance.binary_path = thing
        self.main_instance.original_binary_path = thing
        job = LoadBinaryJob(thing, load_options=load_options, on_finish=on_complete)
        self.main_instance.add_job(job)

    def interact_program(self, img_name, view=None):
        if view is None or view.category != 'interaction':
            view = self._get_or_create_interaction_view()
        view.initialize(img_name)

        self.raise_view(view)
        view.setFocus()

    def log(self, msg):
        if isinstance(msg, BaseException):
            msg = ''.join(traceback.format_exception(type(msg), msg, msg.__traceback__))

        console = self.view_manager.first_view_in_category('console')
        if console is None or not console.ipython_widget_available:
            print(msg)
        else:
            console.print_text(msg)
            console.print_text('\n')

    def show_linear_disassembly_view(self):
        view = self._get_or_create_disassembly_view()
        view.display_linear_viewer()
        self.raise_view(view)
        view.setFocus()

    def show_graph_disassembly_view(self):
        view = self._get_or_create_disassembly_view()
        view.display_disasm_graph()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_linear_disassembly_view(self):
        """
        Create a new disassembly view and select the Linear disassembly mode.
        """
        view = self.new_disassembly_view()
        view.display_linear_viewer()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_graph_disassembly_view(self):
        """
        Create a new disassembly view and select the Graph disassembly mode.
        """
        view = self.new_disassembly_view()
        view.display_disasm_graph()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_hex_view(self):
        """
        Create and show a new hex view.
        """
        view = self._create_hex_view()
        self.raise_view(view)
        view.setFocus()

    def show_pseudocode_view(self):
        """
        Create code view if it does not exist, then show code view.
        """
        view = self._get_or_create_pseudocode_view()
        self.raise_view(view)
        view.setFocus()

    def show_hex_view(self):
        view = self._get_or_create_hex_view()
        self.raise_view(view)
        view.setFocus()

    def show_symexec_view(self):
        view = self._get_or_create_symexec_view()
        self.raise_view(view)
        view.setFocus()

    def show_states_view(self):
        view = self._get_or_create_states_view()
        self.raise_view(view)
        view.setFocus()

    def show_strings_view(self):
        view = self._get_or_create_strings_view()
        self.raise_view(view)
        view.setFocus()

    def show_patches_view(self):
        view = self._get_or_create_patches_view()
        self.raise_view(view)
        view.setFocus()

    def show_interaction_view(self):
        view = self._get_or_create_interaction_view()
        self.raise_view(view)
        view.setFocus()

    def show_types_view(self):
        view = self._get_or_create_types_view()
        self.raise_view(view)
        view.setFocus()

    def show_functions_view(self):
        view = self._get_or_create_functions_view()
        self.raise_view(view)
        view.setFocus()

    def show_traces_view(self):
        view = self._get_or_create_traces_view()
        self.raise_view(view)
        view.setFocus()

    def show_trace_map_view(self):
        view = self._get_or_create_trace_map_view()
        self.raise_view(view)
        view.setFocus()

    def show_registers_view(self):
        view = self._get_or_create_registers_view()
        self.raise_view(view)
        view.setFocus()

    def show_stack_view(self):
        view = self._get_or_create_stack_view()
        self.raise_view(view)
        view.setFocus()

    def show_breakpoints_view(self):
        view = self._get_or_create_breakpoints_view()
        self.raise_view(view)
        view.setFocus()

    def show_call_explorer_view(self):
        view = self._get_or_create_call_explorer_view()
        self.raise_view(view)
        view.setFocus()

    def show_console_view(self):
        view = self._get_or_create_console_view()
        self.raise_view(view)
        view.setFocus()

    def show_log_view(self):
        view = self._get_or_create_log_view()
        self.raise_view(view)
        view.setFocus()

    def toggle_exec_breakpoint(self):
        if self.main_instance is None:
            return

        view: Optional[DisassemblyView] = self.view_manager.first_view_in_category('disassembly')
        if view is not None:
            selected_insns = view.current_graph.infodock.selected_insns
            if selected_insns:
                for insn in selected_insns:
                    self.main_instance.breakpoint_mgr.toggle_exec_breakpoint(insn)

    def step_forward(self, until_addr: Optional[int] = None):
        if self.main_instance is None:
            return

        self.main_instance.debugger_mgr.debugger.step_forward(until_addr=until_addr)

    def continue_forward(self):
        if self.main_instance is None:
            return

        self.main_instance.debugger_mgr.debugger.continue_forward()

    #
    # Private methods
    #

    def _get_or_create_disassembly_view(self) -> DisassemblyView:
        view = self.view_manager.current_view_in_category('disassembly')
        if view is None:
            view = self.view_manager.first_view_in_category('disassembly')
        if view is None:
            view = DisassemblyView(self._main_instance, 'center')
            self.add_view(view)
            view.reload()

        return view

    def _create_hex_view(self) -> HexView:
        """
        Create a new hex view.
        """
        view = HexView(self._main_instance, 'center')
        self.add_view(view)
        return view

    def _get_or_create_hex_view(self) -> HexView:
        view = self.view_manager.first_view_in_category('hex')

        if view is None:
            view = self._create_hex_view()

        return view

    def _get_or_create_pseudocode_view(self):
        # Take the first pseudo-code view
        view = self.view_manager.first_view_in_category("pseudocode")

        if view is None:
            # Create a new pseudo-code view
            view = CodeView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_symexec_view(self):
        # Take the first symexec view
        view = self.view_manager.first_view_in_category("symexec")

        if view is None:
            # Create a new symexec view
            view = SymexecView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_states_view(self):
        # Take the first states view
        view = self.view_manager.first_view_in_category("states")

        if view is None:
            # Create a new states view
            view = StatesView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_strings_view(self):
        # Take the first strings view
        view = self.view_manager.first_view_in_category("strings")

        if view is None:
            # Create a new states view
            view = StringsView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_patches_view(self):
        # Take the first strings view
        view = self.view_manager.first_view_in_category("patches")

        if view is None:
            # Create a new states view
            view = PatchesView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_interaction_view(self):
        view = self.view_manager.first_view_in_category("interaction")
        if view is None:
            # Create a new interaction view
            view = InteractionView(self._main_instance, 'center')
            self.add_view(view)
        return view

    def _get_or_create_types_view(self):
        view = self.view_manager.first_view_in_category("types")
        if view is None:
            # Create a new interaction view
            view = TypesView(self._main_instance, 'center')
            self.add_view(view)
        return view

    def _get_or_create_data_dependency_graph(self, analysis_params: dict) -> Optional[DataDepView]:
        # Take the first data dependency view
        view = self.view_manager.first_view_in_category('data_dependency')

        if view is None:
            # Create a new data dependency view
            view = DataDepView(self._main_instance, 'center')
            self.add_view(view)

        # Update DataDepView to utilize new analysis params
        view.analysis_params = analysis_params

        return view

    def _get_or_create_proximity_view(self) -> ProximityView:
        # Take the first proximity view
        view = self.view_manager.first_view_in_category("proximity")

        if view is None:
            # Create a new proximity view
            view = ProximityView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_console_view(self) -> ConsoleView:
        # Take the first console view
        view = self.view_manager.first_view_in_category("console")

        if view is None:
            # Create a new console view
            view = ConsoleView(self._main_instance, 'bottom')
            self.add_view(view)

        return view

    def _get_or_create_log_view(self) -> LogView:
        # Take the first log view
        view = self.view_manager.first_view_in_category("log")

        if view is None:
            # Create a new log view
            view = LogView(self._main_instance, 'bottom')
            self.add_view(view)

        return view

    def _get_or_create_functions_view(self) -> FunctionsView:
        # Take the first functions view
        view = self.view_manager.first_view_in_category("functions")

        if view is None:
            # Create a new functions view
            view = FunctionsView(self._main_instance, 'left')
            self.add_view(view)

        return view

    def _get_or_create_registers_view(self) -> RegistersView:
        # Take the first registers view
        view = self.view_manager.first_view_in_category("registers")

        if view is None:
            view = RegistersView(self._main_instance, 'right')
            self.add_view(view)

        return view

    def _get_or_create_stack_view(self) -> RegistersView:
        # Take the first stack view
        view = self.view_manager.first_view_in_category("stack")

        if view is None:
            view = StackView(self._main_instance, 'right')
            self.add_view(view)

        return view

    def _get_or_create_traces_view(self) -> TracesView:
        # Take the first traces view
        view = self.view_manager.first_view_in_category("traces")

        if view is None:
            view = TracesView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_trace_map_view(self) -> TraceMapView:
        # Take the first tracemap view
        view = self.view_manager.first_view_in_category("tracemap")

        if view is None:
            view = TraceMapView(self._main_instance, 'top')
            self.add_view(view)

        return view

    def _get_or_create_breakpoints_view(self) -> BreakpointsView:
        # Take the first breakpoints view
        view = self.view_manager.first_view_in_category("breakpoints")

        if view is None:
            view = BreakpointsView(self._main_instance, 'center')
            self.add_view(view)

        return view

    def _get_or_create_call_explorer_view(self) -> CallExplorerView:
        # Take the first function call explorer view
        view = self.view_manager.first_view_in_category('call_explorer')

        if view is None:
            view = CallExplorerView(self._main_instance, 'right')
            self.add_view(view)

        return view

    #
    # UI-related Callback Setters & Manipulation
    #

    # TODO: should these be removed? Nobody is using them and there is equivalent functionality elsewhere.

    def set_cb_function_backcolor(self, callback: Callable[[Function], None]):
        fv = self.view_manager.first_view_in_category('functions')  # type: FunctionsView
        if fv:
            fv.backcolor_callback = callback

    def set_cb_insn_backcolor(self, callback: Callable[[int, bool], None]):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.insn_backcolor_callback = callback

    def set_cb_label_rename(self, callback):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.label_rename_callback = callback

    def add_disasm_insn_ctx_menu_entry(self, text, callback: Callable[[DisasmInsnContextMenu], None],
                                       add_separator_first=True):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.add_menu_entry(text, callback, add_separator_first)

    def remove_disasm_insn_ctx_menu_entry(self, text, remove_preceding_separator=True):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv._insn_menu:
            dv._insn_menu.remove_menu_entry(text, remove_preceding_separator)

    def set_cb_set_comment(self, callback):
        if len(self.view_manager.views_by_category['disassembly']) == 1:
            dv = self.view_manager.first_view_in_category('disassembly')  # type: DisassemblyView
        else:
            dv = self.view_manager.current_view_in_category('disassembly')  # type: DisassemblyView
        if dv:
            dv.set_comment_callback = callback
