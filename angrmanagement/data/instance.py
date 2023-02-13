import logging
import sys
import time
from queue import Queue
from threading import Thread
from typing import TYPE_CHECKING, Callable, List, Optional, Type, Union

import angr
from angr.analyses.disassembly import Instruction
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins import Function
from angr.misc.testing import is_testing
from cle import SymbolType

from angrmanagement.data.breakpoint import Breakpoint, BreakpointManager, BreakpointType
from angrmanagement.data.trace import Trace
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.debugger import DebuggerListManager, DebuggerManager
from angrmanagement.logic.debugger.simgr import SimulationDebugger
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async
from angrmanagement.ui.dialogs import AnalysisOptionsDialog

from .analysis_options import (
    AnalysesConfiguration,
    CFGAnalysisConfiguration,
    FlirtAnalysisConfiguration,
    VariableRecoveryConfiguration,
)
from .jobs import (
    CFGGenerationJob,
    CodeTaggingJob,
    FlirtSignatureRecognitionJob,
    PrototypeFindingJob,
    VariableRecoveryJob,
)
from .log import LogRecord, initialize
from .object_container import ObjectContainer

if TYPE_CHECKING:
    from angrmanagement.ui.workspace import Workspace

_l = logging.getLogger(__name__)


class Instance:
    """
    An object to give access to normal angr project objects like a Project, CFG, and other analyses.
    """

    project: ObjectContainer
    cfg: Union[angr.analyses.cfg.CFGBase, ObjectContainer]
    cfb: Union[angr.analyses.cfg.CFBlanket, ObjectContainer]
    log: Union[List[LogRecord], ObjectContainer]

    def __init__(self):
        # pylint:disable=import-outside-toplevel
        # delayed import
        from angrmanagement.ui.views.interaction_view import (
            BackslashTextProtocol,
            PlainTextProtocol,
            ProtocolInteractor,
            SavedInteraction,
        )

        self._live = False
        self.workspace: Optional["Workspace"] = None
        self.variable_recovery_job: Optional[VariableRecoveryJob] = None
        self._analysis_configuration = None

        self.jobs = []
        self._jobs_queue = Queue()
        self.current_job = None
        self.worker_thread = None

        self.extra_containers = {}
        self._container_defaults = {}

        # where this binary is coming from - if it's loaded from a URL, then original_binary_path will be the URL
        self.original_binary_path = None
        # where this binary is now - if it's loaded from a URL, then binary_path will be its temporary location on the
        # local machine
        self.binary_path = None
        self.register_container("project", lambda: None, Optional[angr.Project], "The current angr project")
        self.register_container("simgrs", lambda: [], List[angr.SimulationManager], "Global simulation managers list")
        self.register_container("states", lambda: [], List[angr.SimState], "Global states list")
        self.register_container("patches", lambda: None, None, "Global patches update notifier")  # dummy
        self.register_container("cfg", lambda: None, Optional[angr.knowledge_plugins.cfg.CFGModel], "The current CFG")
        self.register_container("cfb", lambda: None, Optional[angr.analyses.cfg.CFBlanket], "The current CFBlanket")
        self.register_container("interactions", lambda: [], List[SavedInteraction], "Saved program interactions")
        # TODO: the current setup will erase all loaded protocols on a new project load! do we want that?
        self.register_container(
            "interaction_protocols",
            lambda: [PlainTextProtocol, BackslashTextProtocol],
            List[Type[ProtocolInteractor]],
            "Available interaction protocols",
        )
        self.register_container("log", lambda: [], List[LogRecord], "Saved log messages", logging_permitted=False)
        self.register_container("current_trace", lambda: None, Type[Trace], "Currently selected trace")
        self.register_container("traces", lambda: [], List[Trace], "Global traces list")

        self.register_container("active_view_state", lambda: None, "ViewState", "Currently focused view state")

        self.breakpoint_mgr = BreakpointManager()
        self.debugger_list_mgr = DebuggerListManager()
        self.debugger_mgr = DebuggerManager(self.debugger_list_mgr)

        self.simgrs.am_subscribe(self._update_simgr_debuggers)
        self.project.am_subscribe(self.initialize)

        # Callbacks
        self._insn_backcolor_callback: Optional[Callable[[int, bool], None]] = None  # (addr, is_selected)
        self._label_rename_callback: Optional[Callable[[int, str], None]] = None  # (addr, new_name)
        self._set_comment_callback: Optional[Callable[[int, str], None]] = None  # (addr, comment_text)

        # Setup logging
        initialize(self)

        self.cfg_args = None
        self.variable_recovery_args = None
        self._disassembly = {}
        self.pseudocode_variable_kb = None

        self._start_worker()

        self.database_path = None

        # The image name when loading image
        self.img_name = None

        self._live = True

    #
    # Properties
    #

    @property
    def kb(self) -> Optional[angr.KnowledgeBase]:
        if self.project.am_none:
            return None
        return self.project.kb

    def __getattr__(self, k):
        if k == "extra_containers":
            return {}

        try:
            return self.extra_containers[k]
        except KeyError:
            return super().__getattribute__(k)

    def __setattr__(self, k, v):
        if k in self.extra_containers:
            self.extra_containers[k].am_obj = v
        else:
            super().__setattr__(k, v)

    def __dir__(self):
        return list(super().__dir__()) + list(self.extra_containers)

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
    # Public methods
    #

    def register_container(self, name, default_val_func, ty, description, **kwargs):
        if name in self.extra_containers:
            cur_ty = self._container_defaults[name][1]
            if ty != cur_ty:
                raise Exception(f"Container {name} already registered with different type: {ty} != {cur_ty}")

        else:
            self._container_defaults[name] = (default_val_func, ty)
            self.extra_containers[name] = ObjectContainer(default_val_func(), description, **kwargs)

    def initialize(self, initialized=False, **kwargs):  # pylint:disable=unused-argument
        if self.project.am_none:
            return

        if not initialized:
            if self.pseudocode_variable_kb is None:
                self.initialize_pseudocode_variable_kb()

            gui_thread_schedule_async(self.run_analysis)

        self.workspace.plugins.handle_project_initialization()

    def initialize_pseudocode_variable_kb(self):
        self.pseudocode_variable_kb = KnowledgeBase(self.project.am_obj, name="pseudocode_variable_kb")

    def add_job(self, job):
        self.jobs.append(job)
        self._jobs_queue.put(job)

    def get_instruction_text_at(self, addr):
        """
        Get the text representation of an instruction at `addr`.

        :param int addr:    Address of the instruction.
        :return:            Text representation of the instruction, or None if no instruction can be found there.
        :rtype:             Optional[str]
        """

        if self.cfb is None:
            return None

        try:
            _, obj = self.cfb.floor_item(addr)
        except KeyError:
            # no object before addr exists
            return None

        if isinstance(obj, Block):
            for insn in obj.capstone.insns:
                if insn.address == addr:
                    insn_piece = Instruction(insn, None, project=self.project)
                    return insn_piece.render()[0]
        return None

    def interrupt_current_job(self):
        """Notify the current running job that the user requested an interrupt. The job may ignore it."""
        # Due to thread scheduling, current_job reference *must* first be saved on the stack. Accessing self.current_job
        # multiple times will lead to a race condition.
        current_job = self.current_job
        if current_job:
            current_job.keyboard_interrupt()

    def join_all_jobs(self, wait_period=2.0):
        """
        Wait until self.jobs is empty for at least `wait_period` seconds.

        This is because one job may add another job upon completion. We cannot simply wait until self.jobs becomes
        empty.
        """

        last_has_job = time.time()
        while time.time() - last_has_job <= wait_period:
            while self.jobs:
                last_has_job = time.time()
                time.sleep(0.05)

    def append_code_to_console(self, hook_code_string):
        console = self.workspace._get_or_create_console_view()
        console.set_input_buffer(hook_code_string)

    def delete_hook(self, addr):
        self.project.unhook(addr)

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
            sym = self.project.loader.find_symbol(obj)
            if sym is None:
                _l.error("Couldn't resolve '%s'", obj)
                return
            addr = sym.rebased_addr
            if not size:
                size = sym.size
            if not type_:
                if sym.type == SymbolType.TYPE_FUNCTION:
                    type_ = "execute"
                else:
                    type_ = "write"
        elif type(obj) is Function:
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
        self.breakpoint_mgr.add_breakpoint(bp)

    def set_comment(self, addr, comment_text):
        kb = self.project.kb
        exists = addr in kb.comments

        # callback
        if comment_text is None and exists:
            self.workspace.plugins.handle_comment_changed(addr, "", False, False, False)
            del kb.comments[addr]
        else:
            self.workspace.plugins.handle_comment_changed(addr, comment_text, not exists, False, False)
            kb.comments[addr] = comment_text

        # TODO: can this be removed?
        if self.set_comment_callback:
            self.set_comment_callback(addr=addr, comment_text=comment_text)

    def run_analysis(self, prompt_for_configuration=True):
        if self.project.am_none:
            return

        if self._analysis_configuration is None:
            self._analysis_configuration = AnalysesConfiguration(
                [
                    a(self)
                    for a in [CFGAnalysisConfiguration, FlirtAnalysisConfiguration, VariableRecoveryConfiguration]
                ],
                self,
            )

        if not self.workspace.main_window.shown_at_start:
            # If we are running headlessly (e.g. tests), just run with default configuration
            prompt_for_configuration = False

        if prompt_for_configuration:
            dlg = AnalysisOptionsDialog(self._analysis_configuration, self.workspace, self.workspace.main_window)
            dlg.setModal(True)
            should_run = dlg.exec_()
        else:
            should_run = True

        if should_run:
            if self._analysis_configuration["cfg"].enabled:
                self.generate_cfg(self._analysis_configuration["cfg"].to_dict())

    #
    # Private methods
    #

    @staticmethod
    def _start_daemon_thread(target, name, args=None):
        t = Thread(target=target, name=name, args=args if args else tuple())
        t.daemon = True
        t.start()
        return t

    def _start_worker(self):
        self.worker_thread = self._start_daemon_thread(self._worker, "angr-management Worker Thread")

    def _worker(self):
        while True:
            if self._jobs_queue.empty():
                gui_thread_schedule(GlobalInfo.main_window.progress_done, args=())

            if self.workspace is not None and any(job.blocking for job in self.jobs):
                gui_thread_schedule(self.workspace.main_window._progress_dialog.hide, args=())

            job = self._jobs_queue.get()
            gui_thread_schedule_async(GlobalInfo.main_window.progress, args=("Working...", 0.0))

            if any(job.blocking for job in self.jobs):
                if self.workspace.main_window.isVisible():
                    gui_thread_schedule(self.workspace.main_window._progress_dialog.show, args=())

            try:
                self.current_job = job
                result = job.run(self)
                self.current_job = None
            except (Exception, KeyboardInterrupt) as e:  # pylint: disable=broad-except
                sys.last_traceback = e.__traceback__
                self.current_job = None
                self.workspace.log('Exception while running job "%s":' % job.name)
                self.workspace.log(e)
                self.workspace.log("Type %debug to debug it")
            else:
                gui_thread_schedule_async(job.finish, args=(self, result))

    # pylint:disable=no-self-use
    def _set_status(self, status_text):
        GlobalInfo.main_window.status = status_text

    def _reset_containers(self, **kwargs):
        # pylint:disable=consider-using-dict-items
        for name in self.extra_containers:
            self.extra_containers[name].am_obj = self._container_defaults[name][0]()
            self.extra_containers[name].am_event(**kwargs)

        for dbg in list(self.debugger_list_mgr.debugger_list):
            self.debugger_list_mgr.remove_debugger(dbg)

        self.breakpoint_mgr.clear()

    def _update_simgr_debuggers(self, **kwargs):  # pylint:disable=unused-argument
        sim_dbg = None
        for dbg in self.debugger_list_mgr.debugger_list:
            if isinstance(dbg, SimulationDebugger):
                sim_dbg = dbg
                break

        if len(self.simgrs) > 0:
            if sim_dbg is None:
                view = self.workspace._get_or_create_symexec_view()._simgrs
                dbg = SimulationDebugger(view, self.workspace)
                self.debugger_list_mgr.add_debugger(dbg)
                self.debugger_mgr.set_debugger(dbg)
        elif sim_dbg is not None:
            self.debugger_list_mgr.remove_debugger(sim_dbg)

    #
    # Events
    #

    def generate_cfg(self, cfg_args=None):
        if cfg_args is None:
            cfg_args = {}

        cfg_job = CFGGenerationJob(on_finish=self.on_cfg_generated, **cfg_args)
        self.add_job(cfg_job)
        self._start_daemon_thread(self._refresh_cfg, "Progressively Refreshing CFG", args=(cfg_job,))

    def _refresh_cfg(self, cfg_job):
        """
        Reload once and then refresh in a loop, while the CFG job is running
        """
        reloaded = False
        while True:
            if not self.cfg.am_none:
                if reloaded:
                    gui_thread_schedule_async(
                        self.workspace.refresh,
                        kwargs={
                            "categories": ["disassembly", "functions"],
                        },
                    )
                else:
                    gui_thread_schedule_async(
                        self.workspace.reload,
                        kwargs={
                            "categories": ["disassembly", "functions"],
                        },
                    )
                    reloaded = True

            time.sleep(0.3)
            if cfg_job not in self.jobs:
                break

    def on_cfg_generated(self):
        if self._analysis_configuration["flirt"].enabled:
            self.add_job(
                FlirtSignatureRecognitionJob(
                    on_finish=self._on_flirt_signature_recognized,
                )
            )

        # display the main function if it exists, otherwise display the function at the entry point
        if self.cfg is not None:
            the_func = self.kb.functions.function(name="main")
            if the_func is None:
                the_func = self.kb.functions.function(addr=self.project.entry)

            if the_func is not None:
                self.on_function_selected(the_func)

            # Initialize the linear viewer
            if len(self.workspace.view_manager.views_by_category["disassembly"]) == 1:
                view = self.workspace.view_manager.first_view_in_category("disassembly")
            else:
                view = self.workspace.view_manager.current_view_in_category("disassembly")
            if view is not None:
                view._linear_viewer.initialize()

            # Reload the pseudocode view
            view = self.workspace.view_manager.first_view_in_category("pseudocode")
            if view is not None:
                view.reload()

            # Reload the strings view
            view = self.workspace.view_manager.first_view_in_category("strings")
            if view is not None:
                view.reload()

            # Clear the proximity view
            view = self.workspace.view_manager.first_view_in_category("proximity")
            if view is not None:
                view.clear()

    def _on_flirt_signature_recognized(self):
        self.add_job(
            PrototypeFindingJob(
                on_finish=self._on_prototype_found,
            )
        )

    def _on_prototype_found(self):
        self.add_job(
            CodeTaggingJob(
                on_finish=self.on_function_tagged,
            )
        )

        if self._analysis_configuration["varec"].enabled:
            options = self._analysis_configuration["varec"].to_dict()
            if is_testing:
                # disable multiprocessing on angr CI
                options["workers"] = 0
            self.variable_recovery_job = VariableRecoveryJob(
                **self._analysis_configuration["varec"].to_dict(),
                on_variable_recovered=self.on_variable_recovered,
            )
            # prioritize the current function in display
            disassembly_view = self.workspace.view_manager.first_view_in_category("disassembly")
            if disassembly_view is not None:
                if not disassembly_view.function.am_none:
                    self.variable_recovery_job.prioritize_function(disassembly_view.function.addr)
            self.add_job(self.variable_recovery_job)

    def on_function_selected(self, func: Function):
        """
        Callback function triggered when a new function is selected in the function view.

        :param func:    The function that is selected.
        :return:        None
        """

        # Ask all current views to display this function
        current_view = self.workspace.view_manager.current_tab
        if current_view is None or not current_view.FUNCTION_SPECIFIC_VIEW:
            # we don't have a current view or the current view does not have function-specific content. create a
            # disassembly view to display the selected function.
            disasm_view = self.workspace._get_or_create_disassembly_view()
            disasm_view.display_function(func)
            self.workspace.view_manager.raise_view(disasm_view)
        else:
            # ask the current view to display this function
            current_view.function = func

    def on_function_tagged(self):
        # reload disassembly view
        if len(self.workspace.view_manager.views_by_category["disassembly"]) == 1:
            view = self.workspace.view_manager.first_view_in_category("disassembly")
        else:
            view = self.workspace.view_manager.current_view_in_category("disassembly")

        if view is not None:
            if view.current_function.am_obj is not None:
                view.reload()

    def on_variable_recovered(self, func_addr: int):
        """
        Called when variable information of the given function is available.

        :param int func_addr:   Address of the function whose variable information is available.
        """
        disassembly_view = self.workspace.view_manager.first_view_in_category("disassembly")
        if disassembly_view is not None:
            disassembly_view.on_variable_recovered(func_addr)
