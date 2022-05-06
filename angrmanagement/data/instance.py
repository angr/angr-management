import sys
import time
import logging
from threading import Thread
from queue import Queue
from typing import List, Optional, Type, Union, Callable, TYPE_CHECKING

import angr
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.analyses.disassembly import Instruction

from .jobs import CFGGenerationJob
from .object_container import ObjectContainer
from .log import LogRecord, LogDumpHandler
from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async, gui_thread_schedule
from ..logic.debugger import DebuggerListManager, DebuggerManager
from ..logic.debugger.simgr import SimulationDebugger
from ..data.trace import Trace
from ..data.breakpoint import BreakpointManager

if TYPE_CHECKING:
    from ..ui.workspace import Workspace

class Instance:
    """
    An object to give access to normal angr project objects like a Project, CFG, and other analyses.
    """
    project: Union[angr.Project, ObjectContainer]
    cfg: Union[angr.analyses.cfg.CFGBase, ObjectContainer]
    cfb: Union[angr.analyses.cfg.CFBlanket, ObjectContainer]
    log: Union[List[LogRecord], ObjectContainer]

    def __init__(self):
        # pylint:disable=import-outside-toplevel)
        # delayed import
        from ..ui.views.interaction_view import PlainTextProtocol, BackslashTextProtocol, ProtocolInteractor,\
            SavedInteraction

        self._live = False
        self.workspace: Optional['Workspace'] = None

        self.jobs = []
        self._jobs_queue = Queue()
        self.current_job = None

        self.extra_containers = {}
        self._container_defaults = {}

        # where this binary is coming from - if it's loaded from a URL, then original_binary_path will be the URL
        self.original_binary_path = None
        # where this binary is now - if it's loaded from a URL, then binary_path will be its temporary location on the
        # local machine
        self.binary_path = None
        self.register_container('project', lambda: None, Optional[angr.Project], "The current angr project")
        self.register_container('simgrs', lambda: [], List[angr.SimulationManager], 'Global simulation managers list')
        self.register_container('states', lambda: [], List[angr.SimState], 'Global states list')
        self.register_container('patches', lambda: None, None, 'Global patches update notifier') # dummy
        self.register_container('cfg', lambda: None, Optional[angr.knowledge_plugins.cfg.CFGModel], "The current CFG")
        self.register_container('cfb', lambda: None, Optional[angr.analyses.cfg.CFBlanket], "The current CFBlanket")
        self.register_container('interactions', lambda: [], List[SavedInteraction], 'Saved program interactions')
        # TODO: the current setup will erase all loaded protocols on a new project load! do we want that?
        self.register_container('interaction_protocols',
                                lambda: [PlainTextProtocol, BackslashTextProtocol],
                                List[Type[ProtocolInteractor]],
                                'Available interaction protocols')
        self.register_container('log', lambda: [], List[LogRecord], 'Saved log messages')
        self.register_container('current_trace', lambda: None, Type[Trace], 'Currently selected trace')
        self.register_container('traces', lambda: [], List[Trace], 'Global traces list')

        self.breakpoint_mgr = BreakpointManager()
        self.debugger_list_mgr = DebuggerListManager()
        self.debugger_mgr = DebuggerManager(self.debugger_list_mgr)

        self.simgrs.am_subscribe(self._update_simgr_debuggers)
        self.project.am_subscribe(self.initialize)

        # Callbacks
        self._insn_backcolor_callback = None  # type: Union[None, Callable[[int, bool], None]]   #  (addr, is_selected)
        self._label_rename_callback = None  # type: Union[None, Callable[[int, str], None]]      #  (addr, new_name)
        self._set_comment_callback = None  # type: Union[None, Callable[[int, str], None]]       #  (addr, comment_text)

        self._logging_handler = LogDumpHandler(self)

        # Register a root logger
        logging.root.handlers.insert(0, self._logging_handler)

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
        if k == 'extra_containers':
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

    def register_container(self, name, default_val_func, ty, description):
        if name in self.extra_containers:
            cur_ty = self._container_defaults[name][1]
            if ty != cur_ty:
                raise Exception("Container %s already registered with different type: %s != %s" % (name, ty, cur_ty))

        else:
            self._container_defaults[name] = (default_val_func, ty)
            self.extra_containers[name] = ObjectContainer(default_val_func(), description)

    def initialize(self, initialized=False, cfg_args=None, variable_recovery_args=None, **kwargs):  # pylint:disable=unused-argument
        if self.project.am_none:
            return

        if not initialized:
            if self.pseudocode_variable_kb is None:
                self.initialize_pseudocode_variable_kb()

            if cfg_args is None:
                cfg_args = {}
            # save cfg_args
            self.cfg_args = cfg_args

            if variable_recovery_args is None:
                variable_recovery_args = {}
            self.variable_recovery_args = variable_recovery_args

            # generate CFG
            cfg_job = self.generate_cfg()

            # start daemon
            self._start_daemon_thread(self._refresh_cfg, 'Progressively Refreshing CFG', args=(cfg_job,))
        self.workspace.plugins.handle_project_initialization()

    def initialize_pseudocode_variable_kb(self):
        self.pseudocode_variable_kb = KnowledgeBase(self.project.am_obj, name="pseudocode_variable_kb")

    def generate_cfg(self):
        cfg_job = CFGGenerationJob(
            on_finish=self.workspace.on_cfg_generated,
            **self.cfg_args
        )
        self.add_job(cfg_job)
        return cfg_job

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

    def join_all_jobs(self):
        # ...lol
        while self.jobs:
            time.sleep(0.05)

    def append_code_to_console(self, hook_code_string):
        console = self.workspace._get_or_create_console_view()
        console.set_input_buffer(hook_code_string)

    def delete_hook(self, addr):
        self.project.unhook(addr)

    #
    # Private methods
    #

    @staticmethod
    def _start_daemon_thread(target, name, args=None):
        t = Thread(target=target, name=name, args=args if args else tuple())
        t.daemon = True
        t.start()

    def _start_worker(self):
        self._start_daemon_thread(self._worker, 'angr-management Worker Thread')

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
            except Exception as e: # pylint: disable=broad-except
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

    def _refresh_cfg(self, cfg_job):
        # reload once and then refresh in a loop
        reloaded = False
        while True:
            if not self.cfg.am_none:
                if self.workspace is not None:
                    if reloaded:
                        gui_thread_schedule_async(self.workspace.refresh,
                                                  kwargs={'categories': ['disassembly', 'functions'],}
                                                  )
                    else:
                        gui_thread_schedule_async(self.workspace.reload,
                                                  kwargs={'categories': ['disassembly', 'functions'],}
                                                  )
                        reloaded = True

            time.sleep(0.3)
            if cfg_job not in self.jobs:
                break

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
