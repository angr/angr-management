# pylint:disable=global-statement
from __future__ import annotations

import ctypes
import datetime
import logging
import time
from typing import TYPE_CHECKING

from angrmanagement.logic import GlobalInfo
from angrmanagement.logic.threads import gui_thread_schedule_async

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

m = ...


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def _load_autoreload() -> None:
    """
    Load the autoreload extension module. Delay the import and initialization to reduce angr management's startup time.
    """

    global m
    try:
        from IPython.extensions.autoreload import ModuleReloader  # pylint:disable=import-outside-toplevel

        m = ModuleReloader()
        m.enabled = True
        m.check_all = True
        m.check()
    except ImportError:
        m = None


class Job:
    """
    The base class of all Jobs in angr management.
    """

    def __init__(self, name: str, on_finish=None, blocking: bool = False) -> None:
        self.name = name
        self.progress_percentage = 0.0
        self.last_text: str | None = None
        self.start_at: float = 0.0
        self.last_gui_updated_at: float = 0.0
        self.blocking = blocking

        # callbacks
        self._on_finish = on_finish

        if GlobalInfo.autoreload:
            if m is ...:
                _load_autoreload()
            if m is not None:
                prestate = dict(m.modules_mtimes)
                m.check()
                poststate = dict(m.modules_mtimes)
                if prestate != poststate:
                    log.warning("Auto-reload found changed modules")

    @property
    def time_elapsed(self) -> str:
        return str(datetime.timedelta(seconds=int(time.time() - self.start_at)))

    def run(self, ctx: JobContext, inst: Instance):
        log.info('Job "%s" started', self.name)
        ctx.set_progress(0)
        self.start_at = time.time()
        r = self._run(ctx, inst)
        now = time.time()
        duration = now - self.start_at
        log.info('Job "%s" completed after %.2f seconds', self.name, duration)
        return r

    def _run(self, ctx: JobContext, inst: Instance):
        raise NotImplementedError

    def finish(self, inst, result) -> None:  # pylint: disable=unused-argument
        inst.job_manager.jobs = inst.job_manager.jobs[1:]

        if self._on_finish:
            gui_thread_schedule_async(self._on_finish, (inst, result))

    def keyboard_interrupt(self) -> None:
        """Called from the GUI thread when the user presses Ctrl+C or presses a cancel button"""
        # lol. lmao even.
        if GlobalInfo.main_window.workspace.main_instance.current_job == self:
            tid = GlobalInfo.main_window.workspace.main_instance.worker_thread.ident
            res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(KeyboardInterrupt))
            if res != 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), 0)
                log.error("Failed to interrupt thread")
