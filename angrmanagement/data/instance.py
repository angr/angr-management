import logging
import sys
import time
from queue import Queue
from typing import TYPE_CHECKING, Callable, List, Optional, Type, Union

import angr
from angr.analyses.disassembly import Instruction
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins import Function
from cle import SymbolType

from angrmanagement.data.breakpoint import Breakpoint, BreakpointManager, BreakpointType
from angrmanagement.data.trace import Trace
from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.debugger import DebuggerListManager, DebuggerManager
from angrmanagement.logic.threads import gui_thread_schedule, gui_thread_schedule_async
from angrmanagement.utils.daemon_thread import start_daemon_thread

from .log import LogRecord, initialize
from .object_container import ObjectContainer

if TYPE_CHECKING:
    from .jobs import VariableRecoveryJob


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
        self.register_container("simgrs", list, List[angr.SimulationManager], "Global simulation managers list")
        self.register_container("states", list, List[angr.SimState], "Global states list")
        self.register_container("patches", lambda: None, None, "Global patches update notifier")  # dummy
        self.register_container("cfg", lambda: None, Optional[angr.knowledge_plugins.cfg.CFGModel], "The current CFG")
        self.register_container("cfb", lambda: None, Optional[angr.analyses.cfg.CFBlanket], "The current CFBlanket")
        self.register_container("interactions", list, List[SavedInteraction], "Saved program interactions")
        # TODO: the current setup will erase all loaded protocols on a new project load! do we want that?
        self.register_container(
            "interaction_protocols",
            lambda: [PlainTextProtocol, BackslashTextProtocol],
            List[Type[ProtocolInteractor]],
            "Available interaction protocols",
        )
        self.register_container("log", list, List[LogRecord], "Saved log messages", logging_permitted=False)
        self.register_container("current_trace", lambda: None, Type[Trace], "Currently selected trace")
        self.register_container("traces", list, List[Trace], "Global traces list")

        self.register_container("active_view_state", lambda: None, "ViewState", "Currently focused view state")

        self.breakpoint_mgr = BreakpointManager()
        self.debugger_list_mgr = DebuggerListManager()
        self.debugger_mgr = DebuggerManager(self.debugger_list_mgr)

        self.project.am_subscribe(self.initialize)

        # Callbacks
        self._insn_backcolor_callback: Optional[Callable[[int, bool], None]] = None  # (addr, is_selected)
        self._label_rename_callback: Optional[Callable[[int, str], None]] = None  # (addr, new_name)
        self._set_comment_callback: Optional[Callable[[int, str], None]] = None  # (addr, comment_text)
        self.handle_comment_changed_callback: Optional[Callable[[int, str, bool, bool, bool], None]] = None
        self.job_worker_exception_callback: Optional[Callable[[Exception], None]] = None

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

        self.patches.am_obj = self.kb.patches

        if not initialized and self.pseudocode_variable_kb is None:
            self.initialize_pseudocode_variable_kb()

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
            if obj._using_pcode_engine:
                # TODO: Support getting disassembly from pypcode
                return "..."

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

    def delete_hook(self, addr):
        self.project.unhook(addr)

    def add_breakpoint(self, obj: Union[str, int], type_: Optional[str] = None, size: Optional[int] = None):
        """
        Convenience function to add a breakpoint.

        Examples:
        - `instance.add_breakpoint(0x1234)` sets an execution breakpoint on address 0x1234
        - `instance.add_breakpoint('main')` sets an execution breakpoint on `main` function
        - `instance.add_breakpoint('global_value')` sets a write breakpoint on `global_value`
        - `instance.add_breakpoint('global_value', 'read', 1)` sets a 1-byte read breakpoint on `global_value`
        """
        if isinstance(obj, int):
            addr = obj
        elif isinstance(obj, str):
            sym = self.project.loader.find_symbol(obj)
            if sym is None:
                _l.error("Couldn't resolve '%s'", obj)
                return
            addr = sym.rebased_addr
            if not size:
                size = sym.size
            if not type_:
                type_ = "execute" if sym.type == SymbolType.TYPE_FUNCTION else "write"
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
            if self.handle_comment_changed_callback is not None:
                self.handle_comment_changed_callback(addr, "", False, False, False)
            del kb.comments[addr]
        else:
            if self.handle_comment_changed_callback is not None:
                self.handle_comment_changed_callback(addr, comment_text, not exists, False, False)
            kb.comments[addr] = comment_text

        # TODO: can this be removed?
        if self.set_comment_callback:
            self.set_comment_callback(addr=addr, comment_text=comment_text)

    #
    # Private methods
    #

    # TODO: Worker thread and UI callbacks should be moved to a separate class

    def _start_worker(self):
        self.worker_thread = start_daemon_thread(self._worker, "angr-management Worker Thread")

    def _worker(self):
        while True:
            if self._jobs_queue.empty():
                callback_worker_progress_empty()

            if any(job.blocking for job in self.jobs):
                callback_worker_blocking_job()

            job = self._jobs_queue.get()
            callback_worker_new_job()

            if any(job.blocking for job in self.jobs):
                callback_worker_blocking_job_2()

            try:
                self.current_job = job
                result = job.run(self)
                self.current_job = None
            except (Exception, KeyboardInterrupt) as e:  # pylint: disable=broad-except
                sys.last_traceback = e.__traceback__
                self.current_job = None
                _l.exception('Exception while running job "%s":', job.name)
                if self.job_worker_exception_callback is not None:
                    self.job_worker_exception_callback(job, e)
            else:
                callback_job_complete(self, job, result)

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


def callback_worker_progress_empty():
    gui_thread_schedule(GlobalInfo.main_window.progress_done, args=())


def callback_worker_blocking_job():
    if GlobalInfo.main_window is not None and GlobalInfo.main_window.workspace:
        gui_thread_schedule(GlobalInfo.main_window._progress_dialog.hide, args=())


def callback_worker_new_job():
    gui_thread_schedule_async(GlobalInfo.main_window.progress, args=("Working...", 0.0, True))


def callback_worker_blocking_job_2():
    if GlobalInfo.main_window.isVisible():
        gui_thread_schedule(GlobalInfo.main_window._progress_dialog.show, args=())


def callback_job_complete(instance, job, result):
    gui_thread_schedule_async(job.finish, args=(instance, result))
