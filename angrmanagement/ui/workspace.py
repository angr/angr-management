from __future__ import annotations

import logging
import os
import time
import traceback
from typing import TYPE_CHECKING, TypeVar

from angr import StateHierarchy
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.patches import Patch
from angr.misc.testing import is_testing
from cle import SymbolType
from PySide6.QtWidgets import QMessageBox
from PySide6QtAds import SideBarBottom

from angrmanagement.config import Conf
from angrmanagement.data.analysis_options import (
    AnalysesConfiguration,
    CFGAnalysisConfiguration,
    CodeTaggingConfiguration,
    FlirtAnalysisConfiguration,
    VariableRecoveryConfiguration,
)
from angrmanagement.data.breakpoint import Breakpoint, BreakpointType
from angrmanagement.data.instance import Instance, ObjectContainer
from angrmanagement.data.jobs import (
    CFGGenerationJob,
    CodeTaggingJob,
    FlirtSignatureRecognitionJob,
    Job,
    PrototypeFindingJob,
    VariableRecoveryJob,
)
from angrmanagement.data.jobs.loading import LoadBinaryJob
from angrmanagement.data.trace import BintraceTrace, Trace
from angrmanagement.logic.commands import CommandManager
from angrmanagement.logic.debugger import DebuggerWatcher
from angrmanagement.logic.debugger.bintrace import BintraceDebugger
from angrmanagement.logic.debugger.simgr import SimulationDebugger
from angrmanagement.logic.jobmanager import JobManager
from angrmanagement.logic.threads import gui_thread_schedule_async
from angrmanagement.plugins import PluginManager
from angrmanagement.ui.dialogs import AnalysisOptionsDialog
from angrmanagement.ui.dialogs.function import FunctionDialog
from angrmanagement.ui.views.view import FunctionView
from angrmanagement.utils import locate_function
from angrmanagement.utils.daemon_thread import start_daemon_thread

from .view_manager import ViewManager
from .views import (
    BaseView,
    BreakpointsView,
    CallExplorerView,
    CodeView,
    ConsoleView,
    DataDepView,
    DependencyView,
    DisassemblyView,
    FunctionsView,
    HexView,
    InteractionView,
    JobsView,
    LogView,
    PatchesView,
    ProximityView,
    RegistersView,
    StackView,
    StatesView,
    StringsView,
    SymexecView,
    TraceMapView,
    TracesView,
    TypesView,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from angrmanagement.ui.main_window import MainWindow


_l = logging.getLogger(__name__)
T = TypeVar("T")


class Workspace:
    """
    This class implements the angr management workspace.
    """

    job_manager: JobManager

    def __init__(self, main_window: MainWindow) -> None:
        self.main_window: MainWindow = main_window
        self.job_manager = JobManager(self)

        self.command_manager: CommandManager = CommandManager()
        self.view_manager: ViewManager = ViewManager(self)
        self.plugins: PluginManager = PluginManager(self)
        self.variable_recovery_job: VariableRecoveryJob | None = None
        self._first_cfg_generation_callback_completed: bool = False

        self._main_instance = Instance()

        # Configure callbacks on main_instance
        self.main_instance.project.am_subscribe(self._instance_project_initalization)
        self.main_instance.simgrs.am_subscribe(self._update_simgr_debuggers)
        self.main_instance.handle_comment_changed_callback = self.plugins.handle_comment_changed
        self.main_instance.job_worker_exception_callback = self._handle_job_exception

        self.current_screen = ObjectContainer(None, name="current_screen")

        self.default_tabs = [
            DisassemblyView(self, "center", self._main_instance),
            HexView(self, "center", self._main_instance),
            CodeView(self, "center", self._main_instance),
            FunctionsView(self, "left", self._main_instance),
        ]
        if Conf.has_operation_mango:
            self.default_tabs.append(DependencyView(self, "center", self._main_instance))
        minimized_tabs = [
            ConsoleView(self, "bottom", self._main_instance),
            LogView(self, "bottom", self._main_instance),
            JobsView(self, "bottom", self.main_instance),
        ]
        self.default_tabs += minimized_tabs

        enabled_tabs = [x.strip() for x in Conf.enabled_tabs.split(",") if x.strip()]
        for tab in self.default_tabs:
            if tab.__class__.__name__ in enabled_tabs or len(enabled_tabs) == 0:
                self.add_view(tab)

        for view in minimized_tabs:
            dock = self.view_manager.view_to_dock.get(view, None)
            if dock is not None:
                dock.setAutoHide(True, SideBarBottom)

        self._dbg_watcher = DebuggerWatcher(self.on_debugger_state_updated, self.main_instance.debugger_mgr.debugger)
        self.on_debugger_state_updated()

        DisassemblyView.register_commands(self)

        self.main_instance.patches.am_subscribe(self._on_patch_event)

    #
    # Properties
    #

    @property
    def _main_window(self) -> MainWindow:
        return self.main_window

    @property
    def main_instance(self) -> Instance:
        return self._main_instance

    #
    # Events
    #

    def on_debugger_state_updated(self) -> None:
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
                view = self.view_manager.current_view_in_category(
                    "disassembly"
                ) or self.view_manager.first_view_in_category("disassembly")
                if view:
                    view.jump_to(addr, True)

    def on_function_selected(self, func: Function) -> None:
        """
        Callback function triggered when a new function is selected in the function view.

        :param func:    The function that is selected.
        :return:        None
        """

        # Ask all current views to display this function
        current_view = self.view_manager.current_tab
        if current_view is None or not isinstance(current_view, FunctionView):
            # we don't have a current view or the current view does not have function-specific content. create a
            # disassembly view to display the selected function.
            disasm_view = self._get_or_create_view("dissasembly", DisassemblyView)
            disasm_view.display_function(func)
            self.view_manager.raise_view(disasm_view)
        else:
            # ask the current view to display this function
            current_view.function = func

    def on_function_tagged(self, _: Any) -> None:
        # reload disassembly view
        if len(self.view_manager.views_by_category["disassembly"]) == 1:
            view = self.view_manager.first_view_in_category("disassembly")
        else:
            view = self.view_manager.current_view_in_category("disassembly")

        if view is not None and view.current_function.am_obj is not None:
            view.reload()

    def on_variable_recovered(self, func_addr: int) -> None:
        """
        Called when variable information of the given function is available.

        :param int func_addr:   Address of the function whose variable information is available.
        """
        disassembly_view = self.view_manager.first_view_in_category("disassembly")
        if disassembly_view is not None:
            disassembly_view.on_variable_recovered(func_addr)

    def generate_cfg(self, cfg_args=None) -> None:
        if cfg_args is None:
            cfg_args = {}

        cfg_job = CFGGenerationJob(self.main_instance, on_finish=self.on_cfg_generated, **cfg_args)
        self.job_manager.add_job(cfg_job)
        start_daemon_thread(self._refresh_cfg, "Progressively Refreshing CFG", args=(cfg_job,))

    def _refresh_cfg(self, cfg_job) -> None:
        """
        Reload once and then refresh in a loop, while the CFG job is running
        """
        reloaded = False
        while True:
            if not self.main_instance.cfg.am_none:
                if reloaded:
                    gui_thread_schedule_async(
                        self.refresh,
                        kwargs={
                            "categories": ["disassembly", "functions"],
                        },
                    )
                else:
                    gui_thread_schedule_async(
                        self.reload,
                        kwargs={
                            "categories": ["disassembly", "functions"],
                        },
                    )
                    reloaded = True

            time.sleep(0.3)
            if cfg_job not in self.job_manager.jobs:
                break

    def on_cfg_generated(self, cfg_result) -> None:
        cfg, cfb = cfg_result
        self.main_instance.cfb = cfb
        self.main_instance.cfg = cfg
        self.main_instance.cfb.am_event()
        self.main_instance.cfg.am_event()

        if self.main_instance._analysis_configuration["flirt"].enabled:
            self.job_manager.add_job(
                FlirtSignatureRecognitionJob(
                    self.main_instance,
                    on_finish=self._on_flirt_signature_recognized,
                )
            )

        if not self.main_instance.cfg.am_none:
            if not self._first_cfg_generation_callback_completed:
                self._first_cfg_generation_callback_completed = True
                the_func = self.main_instance.kb.functions.function(name="main")
                if the_func is None:
                    the_func = self.main_instance.kb.functions.function(addr=self.main_instance.project.entry)
                if the_func is not None:
                    self.on_function_selected(the_func)

            # Reload the pseudocode view
            view = self.view_manager.first_view_in_category("pseudocode")
            if view is not None:
                view.reload()

            # Reload the strings view
            view = self.view_manager.first_view_in_category("strings")
            if view is not None:
                view.reload()

            # Clear the proximity view
            view = self.view_manager.first_view_in_category("proximity")
            if view is not None:
                view.clear()

    def _on_flirt_signature_recognized(self, _: Any) -> None:
        self.job_manager.add_job(
            PrototypeFindingJob(
                self.main_instance,
                on_finish=self._on_prototype_found,
            )
        )

    def _on_prototype_found(self, _: Any) -> None:
        if self.main_instance._analysis_configuration["code_tagging"].enabled:
            self.job_manager.add_job(
                CodeTaggingJob(
                    self.main_instance,
                    on_finish=self.on_function_tagged,
                )
            )

        if self.main_instance._analysis_configuration["varec"].enabled:
            options = self.main_instance._analysis_configuration["varec"].to_dict()
            if is_testing:
                # disable multiprocessing on angr CI
                options["workers"] = 0
            self.main_instance.variable_recovery_job = VariableRecoveryJob(
                self.main_instance,
                **self.main_instance._analysis_configuration["varec"].to_dict(),
                on_variable_recovered=self.on_variable_recovered,
            )
            # prioritize the current function in display
            disassembly_view = self.view_manager.first_view_in_category("disassembly")
            if disassembly_view is not None and not disassembly_view.function.am_none:
                self.main_instance.variable_recovery_job.prioritize_function(disassembly_view.function.addr)
            self.job_manager.add_job(self.main_instance.variable_recovery_job)

    def _on_patch_event(self, **kwargs) -> None:
        if self.main_instance.cfg.am_none:
            return

        update_cfg = False
        for k in ("added", "removed"):
            for patch in kwargs.get(k, set()):
                self.main_instance.cfg.clear_region_for_reflow(
                    patch.addr, len(patch.new_bytes), self.main_instance.project.kb
                )
                update_cfg = True

        if update_cfg:
            self.generate_cfg(
                cfg_args={
                    "force_smart_scan": False,
                    "force_complete_scan": False,
                    "model": self.main_instance.kb.cfgs.get_most_accurate(),
                    # FIXME: We don't want to force scan the entire binary, just the patched region. Add an
                    #        option for it.
                }
            )

    #
    # Public methods
    #

    def new_disassembly_view(self) -> DisassemblyView:
        """
        Add a new disassembly view.
        """
        disassembly_view = self.view_manager.first_view_in_category("disassembly")
        current_addr = disassembly_view.jump_history.current if disassembly_view is not None else None

        view = DisassemblyView(self, "center", self._main_instance)
        self.add_view(view)
        self.raise_view(view)
        view._linear_viewer.initialize()  # FIXME: Don't access protected member
        if current_addr is not None:
            view.jump_to(current_addr)
        # TODO move view tab to front of dock
        return view

    def add_view(self, view) -> None:
        self.view_manager.add_view(view)

    def remove_view(self, view) -> None:
        self.view_manager.remove_view(view)

    def raise_view(self, view) -> None:
        """
        Find the dock widget of a view, and then bring that dockable to front.

        :param BaseView view: The view to raise.
        :return:              None
        """

        self.view_manager.raise_view(view)

    def reload(self, categories: list[str] | None = None) -> None:
        """
        Ask all or specified views to reload the underlying data and regenerate the UI. This is usually expensive.

        :param categories:  Specify a list of view categories that should be reloaded.
        :return:            None
        """

        if categories is None:
            views = self.view_manager.views
        else:
            views = []
            for category in categories:
                views.extend(self.view_manager.views_by_category.get(category, []))

        for view in views:
            try:
                view.reload()
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

    def refresh(self, categories: list[str] | None = None) -> None:
        """
        Ask all or specified views to refresh based on changes in the underlying data and refresh the UI if needed. This
        may be called frequently so it must be extremely fast.

        :param categories:  Specify a list of view categories that should be reloaded.
        :return:            None
        """

        if categories is None:
            views = self.view_manager.views
        else:
            views = []
            for category in categories:
                views.extend(self.view_manager.views_by_category.get(category, []))

        for view in views:
            try:
                view.refresh()
            except Exception:  # pylint:disable=broad-except
                _l.warning("Exception occurred during reloading view %s.", view, exc_info=True)

    def viz(self, obj) -> None:
        """
        Visualize the given object.

        - For integers, open the disassembly view and jump to that address
        - For Function objects, open the disassembly view and jump there
        - For strings, look up the symbol of that name and jump there
        """

        if isinstance(obj, int):
            self.jump_to(obj)
        elif isinstance(obj, str):
            sym = self.main_instance.project.loader.find_symbol(obj)
            if sym is not None:
                self.jump_to(sym.rebased_addr)
        elif isinstance(obj, Function):
            self.jump_to(obj.addr)

    def jump_to(self, addr: int, view=None, use_animation: bool = False) -> None:
        if view is None or view.category != "disassembly":
            view = self._get_or_create_view("disassembly", DisassemblyView)

        self.raise_view(view)
        view.setFocus()
        view.jump_to(addr, use_animation=use_animation)

    def add_breakpoint(self, obj: str | int, type_: str | None = None, size: int | None = None) -> None:
        """
        Convenience function to add a breakpoint.

        Examples:
        - `workspace.add_breakpoint(0x1234)` sets an execution breakpoint on address 0x1234
        - `workspace.add_breakpoint('main')` sets an execution breakpoint on `main` function
        - `workspace.add_breakpoint('global_value')` sets a write breakpoint on `global_value`
        - `workspace.add_breakpoint('global_value', 'read', 1)` sets a 1-byte read breakpoint on `global_value`
        """
        if isinstance(obj, int):
            addr = obj
        elif isinstance(obj, str):
            sym = self.main_instance.project.loader.find_symbol(obj)
            if sym is None:
                _l.error("Couldn't resolve '%s'", obj)
                return
            addr = sym.rebased_addr
            if not size:
                size = sym.size
            if not type_:
                type_ = "execute" if sym.type == SymbolType.TYPE_FUNCTION else "write"
        elif isinstance(obj, Function):
            addr = obj.addr
            if not type_:
                type_ = "execute"
        else:
            _l.error("Unexpected target object type. Expected int | str | Function")
            return

        if not size:
            size = 1

        bp_type_map = {
            None: BreakpointType.Execute,
            "execute": BreakpointType.Execute,
            "write": BreakpointType.Write,
            "read": BreakpointType.Read,
        }
        if type_ not in bp_type_map:
            _l.error("Unknown breakpoint type '%s'. Expected %s", type_, " | ".join(bp_type_map.keys()))
            return

        bp = Breakpoint(bp_type_map[type_], addr, size)
        self.main_instance.breakpoint_mgr.add_breakpoint(bp)

    def set_comment(self, addr: int, comment_text) -> None:
        self.main_instance.set_comment(addr, comment_text)

        disasm_view = self._get_or_create_view("disassembly", DisassemblyView)
        if disasm_view._flow_graph.disasm is not None:
            # redraw
            disasm_view.current_graph.refresh()

    def run_analysis(self, prompt_for_configuration: bool = True) -> None:
        if self.main_instance.project.am_none:
            return

        if not self.main_window.shown_at_start:
            # If we are running headlessly (e.g. tests), just run with default configuration
            prompt_for_configuration = False

        if self.main_instance._analysis_configuration is None:
            self.main_instance._analysis_configuration = AnalysesConfiguration(
                [
                    a(self.main_instance)
                    for a in [
                        CFGAnalysisConfiguration,
                        FlirtAnalysisConfiguration,
                        CodeTaggingConfiguration,
                        VariableRecoveryConfiguration,
                    ]
                ],
                self,
            )

        if prompt_for_configuration:
            dlg = AnalysisOptionsDialog(self.main_instance._analysis_configuration, self, self.main_window)
            dlg.setModal(True)
            should_run = dlg.exec_()
        else:
            should_run = True

        if should_run and self.main_instance._analysis_configuration["cfg"].enabled:
            cfg_options = self.main_instance._analysis_configuration["cfg"].to_dict()
            # update function start locations
            if "function_starts" in cfg_options:
                function_starts = []
                for func_start_str in cfg_options["function_starts"].split(","):
                    func_start_str = func_start_str.strip(" ")
                    if not func_start_str:
                        continue

                    try:
                        func_addr = int(func_start_str, 16)
                    except ValueError:
                        if prompt_for_configuration:
                            QMessageBox.critical(
                                None, "Invalid function start string", f"Invalid analysis start {func_start_str}."
                            )
                        return

                    function_starts.append(func_addr)

                if function_starts:
                    if "explicit_analysis_starts" in cfg_options:
                        cfg_options["elf_eh_frame"] = False
                        cfg_options["symbols"] = False
                        cfg_options["start_at_entry"] = False

                    cfg_options["function_starts"] = function_starts

            # discard "explicit_analysis_starts" even if function_starts is not set
            if "explicit_analysis_starts" in cfg_options:
                del cfg_options["explicit_analysis_starts"]

            # update options for region specification
            if "regions" in cfg_options:
                regions = []
                for region_str in cfg_options["regions"].split(","):
                    region_str = region_str.strip(" ")
                    if not region_str:
                        continue
                    if "-" not in region_str or region_str.count("-") != 1:
                        # invalid region
                        if prompt_for_configuration:
                            QMessageBox.critical(
                                None, "Invalid region setting", f"Invalid analysis region {region_str}."
                            )
                        return
                    min_addr, max_addr = region_str.split("-")
                    try:
                        min_addr = int(min_addr, 16)
                    except ValueError:
                        if prompt_for_configuration:
                            QMessageBox.critical(
                                None, "Invalid region setting", f"Invalid analysis region {region_str}."
                            )
                        return
                    try:
                        max_addr = int(max_addr, 16)
                    except ValueError:
                        if prompt_for_configuration:
                            QMessageBox.critical(
                                None, "Invalid region setting", f"Invalid analysis region {region_str}."
                            )
                        return
                    regions.append((min_addr, max_addr))
                if regions:
                    cfg_options["regions"] = regions

            self.generate_cfg(cfg_options)

    def decompile_current_function(self) -> None:
        current = self.view_manager.current_tab
        if isinstance(current, CodeView):
            current.decompile()
        else:
            view = self._get_or_create_view("disassembly", DisassemblyView)
            view.decompile_current_function()

    def view_data_dependency_graph(self, analysis_params: dict) -> None:
        view = self._get_or_create_view("data_dependency", DataDepView)
        view.analysis_params = analysis_params
        self.raise_view(view)

    def view_proximity_for_current_function(self, view=None) -> None:
        if view is None or view.category != "proximity":
            view = self._get_or_create_view("proximity", ProximityView)

        disasm_view = self._get_or_create_view("disassembly", DisassemblyView)
        if disasm_view.current_function is not None:
            view.function = disasm_view.current_function.am_obj

        self.raise_view(view)

    def decompile_function(self, func: Function, curr_ins=None, view=None) -> None:
        """
        Decompile a function and switch to decompiled view. If curr_ins is
        defined, then also switch cursor focus to the position associated
        with the asm instruction addr

        :param func: The function to decompile
        :param curr_ins: The instruction the cursor was at before switching to decompiled view
        :param view: The decompiled qt text view
        :return:
        """

        if view is None or view.category != "pseudocode":
            view = self._get_or_create_view("pseudocode", CodeView)

        view.function.am_obj = func
        view.function.am_event(focus=True, focus_addr=curr_ins)

    def create_simulation_manager(self, state, state_name: str, view=None) -> None:
        inst = self.main_instance
        hierarchy = StateHierarchy()
        simgr = inst.project.factory.simulation_manager(state, hierarchy=hierarchy)
        simgr_container = ObjectContainer(simgr, name=state_name)
        inst.simgrs.append(simgr_container)
        inst.simgrs.am_event(src="new_path")

        if view is None:
            view = self._get_or_create_view("symexec", SymexecView)
        view.select_simgr(simgr_container)

        self.raise_view(view)

    def create_trace_debugger(self) -> None:
        if self.main_instance.current_trace.am_none:
            _l.error("No trace available")
            return

        if isinstance(self.main_instance.current_trace.am_obj, BintraceTrace):
            dbg = BintraceDebugger(self.main_instance.current_trace.am_obj, self)
            dbg.init()
            self.main_instance.debugger_list_mgr.add_debugger(dbg)
            self.main_instance.debugger_mgr.set_debugger(dbg)

    def is_current_trace(self, trace: Trace | None) -> bool:
        return self.main_instance.current_trace.am_obj is trace

    def set_current_trace(self, trace: Trace | None) -> None:
        self.main_instance.current_trace.am_obj = trace
        self.main_instance.current_trace.am_event()

    def remove_trace(self, trace: Trace) -> None:
        if self.is_current_trace(trace):
            self.set_current_trace(None)
        self.main_instance.traces.remove(trace)
        self.main_instance.traces.am_event(trace_removed=trace)
        # Note: Debuggers and other objects may retain trace

    def load_trace_from_path(self, path: str) -> None:
        if not BintraceTrace.trace_backend_enabled():
            QMessageBox.critical(None, "Error", "bintrace is not installed. Please install the bintrace package.")
            return

        _l.info("Opening trace %s", path)
        trace = BintraceTrace.load_trace(path)

        def on_complete(*args, **kwargs) -> None:  # pylint:disable=unused-argument
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

    def create_project_from_trace(self, trace: Trace, on_complete: Callable) -> None:
        thing = None
        load_options = trace.get_project_load_options()

        if load_options is None:
            QMessageBox.warning(
                None, "Error", "Failed to determine load options for binary from trace. Please select binary."
            )
            load_options = {}
        else:
            thing = load_options["thing"]
            load_options = load_options["load_options"]
            if not os.path.exists(thing):
                QMessageBox.warning(
                    None,
                    "Unable to find target binary!",
                    f"Unable to find the traced binary at: \n\n{thing}\n\nPlease select target binary.",
                )
                thing = None

        if not thing:
            thing = self.main_window.open_mainfile_dialog()

        if not thing:
            on_complete()
            return

        self.main_instance.binary_path = thing
        self.main_instance.original_binary_path = thing
        job = LoadBinaryJob(self.main_instance, thing, load_options=load_options, on_finish=on_complete)
        self.job_manager.add_job(job)

    def interact_program(self, img_name: str, view=None) -> None:
        if view is None or view.category != "interaction":
            view = self._get_or_create_view("interaction", InteractionView)
        view.initialize(img_name)

        self.raise_view(view)
        view.setFocus()

    def log(self, msg) -> None:
        if isinstance(msg, BaseException):
            msg = "".join(traceback.format_exception(type(msg), msg, msg.__traceback__))

        console = self.view_manager.first_view_in_category("console")
        if console is None or not console.ipython_widget_available:
            print(msg)
        else:
            console.print_text(msg)
            console.print_text("\n")

    def show_view(self, category: str, type_: type[BaseView], position: str = "center") -> None:
        view = self._get_or_create_view(category, type_, position=position)
        self.raise_view(view)
        view.setFocus()

    def show_linear_disassembly_view(self) -> None:
        view = self._get_or_create_view("disassembly", DisassemblyView, position="center")
        view.display_linear_viewer()
        self.raise_view(view)
        view.setFocus()

    def show_graph_disassembly_view(self) -> None:
        view = self._get_or_create_view("disassembly", DisassemblyView, position="center")
        view.display_disasm_graph()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_linear_disassembly_view(self) -> None:
        """
        Create a new disassembly view and select the Linear disassembly mode.
        """
        view = self.new_disassembly_view()
        view.display_linear_viewer()
        self.raise_view(view)
        view.setFocus()

    def create_and_show_graph_disassembly_view(self) -> None:
        """
        Create a new disassembly view and select the Graph disassembly mode.
        """
        view = self.new_disassembly_view()
        view.display_disasm_graph()
        self.raise_view(view)
        view.setFocus()

    def show_pseudocode_view(self) -> None:
        self.show_view("pseudocode", CodeView)

    def show_hex_view(self) -> None:
        self.show_view("hex", HexView)

    def show_symexec_view(self) -> None:
        self.show_view("symexec", SymexecView)

    def show_states_view(self) -> None:
        self.show_view("states", StatesView)

    def show_strings_view(self) -> None:
        self.show_view("strings", StringsView)

    def show_patches_view(self) -> None:
        self.show_view("patches", PatchesView)

    def show_interaction_view(self) -> None:
        self.show_view("interaction", InteractionView)

    def show_types_view(self) -> None:
        self.show_view("types", TypesView)

    def show_functions_view(self) -> None:
        self.show_view("functions", FunctionsView, position="left")

    def show_traces_view(self) -> None:
        self.show_view("traces", TracesView)

    def show_trace_map_view(self) -> None:
        self.show_view("tracemap", TraceMapView, position="top")

    def show_registers_view(self) -> None:
        self.show_view("registers", RegistersView, position="right")

    def show_stack_view(self) -> None:
        self.show_view("stack", StackView, position="right")

    def show_breakpoints_view(self) -> None:
        self.show_view("breakpoints", BreakpointsView)

    def show_call_explorer_view(self) -> None:
        self.show_view("call_explorer", CallExplorerView)

    def show_console_view(self) -> None:
        self.show_view("console", ConsoleView, position="bottom")

    def show_log_view(self) -> None:
        self.show_view("log", LogView, position="bottom")

    def create_and_show_hex_view(self):
        view = HexView(self, "center", self._main_instance)
        self.add_view(view)
        return view

    def toggle_exec_breakpoint(self) -> None:
        if self.main_instance is None:
            return

        view: DisassemblyView | None = self.view_manager.first_view_in_category("disassembly")
        if view is not None:
            selected_insns = view.current_graph.infodock.selected_insns
            if selected_insns:
                for insn in selected_insns:
                    self.main_instance.breakpoint_mgr.toggle_exec_breakpoint(insn)

    def step_forward(self, until_addr: int | None = None) -> None:
        if self.main_instance is None:
            return

        self.main_instance.debugger_mgr.debugger.step_forward(until_addr=until_addr)

    def continue_forward(self) -> None:
        if self.main_instance is None:
            return

        self.main_instance.debugger_mgr.debugger.continue_forward()

    def append_code_to_console(self, hook_code_string: str) -> None:
        console = self._get_or_create_view("console", ConsoleView)
        console.set_input_buffer(hook_code_string)

    def patch(self, addr: int, asm: str, pad: bool = True) -> None:
        ks = self.main_instance.project.arch.keystone
        block = self.main_instance.project.factory.block(addr)
        insn = block.disassembly.insns[0]
        original_bytes: bytes = self.main_instance.project.loader.memory.load(insn.address, insn.size)
        ks = self.main_instance.project.arch.keystone
        new_bytes = (ks.asm(asm, addr, as_bytes=True)[0] or b"") if len(asm) else b""

        # Pad to original instruction length
        byte_length_delta = len(original_bytes) - len(new_bytes)
        if byte_length_delta > 0:
            if pad:
                nop_instruction_bytes = self.main_instance.project.arch.nop_instruction
                new_bytes += (byte_length_delta // len(nop_instruction_bytes)) * nop_instruction_bytes
                byte_length_delta = len(original_bytes) - len(new_bytes)
                if byte_length_delta:
                    _l.warning("Unable to completely pad remainder")
        elif byte_length_delta < 0:
            _l.warning("Patch exceeds original instruction length")

        pm = self.main_instance.project.kb.patches
        patch = Patch(addr, new_bytes)
        pm.add_patch_obj(patch)
        self.main_instance.patches.am_event(added={patch})

    def define_code(self, addr: int) -> None:
        cfg = self.main_instance.cfg
        if cfg.am_none:
            _l.error("Run initial CFG analysis before defining code")
            return

        func = locate_function(self.main_instance, addr)
        if func is not None:
            _l.warning("Address %#x is already defined as code", addr)
            return

        # Attempt flow into preceding function
        func = cfg.find_function_for_reflow_into_addr(addr)
        if func:
            cfg.clear_region_for_reflow(func.addr)

        # Truncate existing memory data
        if addr in cfg.memory_data:
            del cfg.memory_data[addr]
        for md in cfg.memory_data.values():
            if md.size and md.addr < addr < (md.addr + md.size):
                md.size = addr - md.addr

        self.generate_cfg(
            cfg_args={
                "symbols": False,
                "function_prologues": False,
                "start_at_entry": False,
                "force_smart_scan": False,
                "force_complete_scan": False,
                "function_starts": [func.addr if func else addr],
                "model": self.main_instance.kb.cfgs.get_most_accurate(),
            }
        )

    def undefine_code(self, addr: int) -> None:
        cfg = self.main_instance.cfg
        if cfg.am_none:
            _l.error("Run initial CFG analysis before undefining code")
            return

        func = locate_function(self.main_instance, addr)
        if func is None:
            _l.warning("Could not determine function for addr %#x", addr)
            return

        md = MemoryData(addr, 1, MemoryDataSort.Integer)  # FIXME: Type, expand size
        cfg.memory_data[md.addr] = md.copy()
        cfg.clear_region_for_reflow(func.addr)

        self.generate_cfg(
            cfg_args={
                "symbols": False,
                "function_prologues": False,
                "start_at_entry": False,
                "force_smart_scan": False,
                "force_complete_scan": False,
                "function_starts": [func.addr],
                "model": self.main_instance.kb.cfgs.get_most_accurate(),
            }
        )

    def show_function_info(self, function: str | int | Function) -> None:
        if isinstance(function, str | int):
            function = self.main_instance.project.kb.functions[function]
        FunctionDialog(function).exec_()

    #
    # Instance Callbacks
    #
    def _instance_project_initalization(self, **kwargs) -> None:  # pylint:disable=unused-argument
        if self.main_instance.project.am_none:
            return

        # trigger more analyses if we don't have at least one CFG available
        if not self.main_instance.kb.cfgs.cfgs:
            gui_thread_schedule_async(self.run_analysis)

        self.plugins.handle_project_initialization()

    def _handle_job_exception(self, job: Job, e: Exception) -> None:
        self.log(f'Exception while running job "{job.name}":')
        self.log(e)
        self.log("Type %debug to debug it")

    def _update_simgr_debuggers(self, **kwargs) -> None:  # pylint:disable=unused-argument
        sim_dbg = None
        for dbg in self.main_instance.debugger_list_mgr.debugger_list:
            if isinstance(dbg, SimulationDebugger):
                sim_dbg = dbg
                break

        if len(self.main_instance.simgrs) > 0:
            if sim_dbg is None:
                simgrs = self._get_or_create_view("symexec", SymexecView)._simgrs
                dbg = SimulationDebugger(simgrs, self)
                self.main_instance.debugger_list_mgr.add_debugger(dbg)
                self.main_instance.debugger_mgr.set_debugger(dbg)
        elif sim_dbg is not None:
            self.main_instance.debugger_list_mgr.remove_debugger(sim_dbg)

    #
    # Private methods
    #

    def _get_or_create_view(self, category: str, view_type: type[T], position: str = "center") -> T:
        view = self.view_manager.current_view_in_category(category)
        if view is None:
            view = self.view_manager.first_view_in_category(category)
        if view is None:
            view = view_type(self, position, self._main_instance)
            self.add_view(view)
        return view
