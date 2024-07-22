# pylint:disable=global-statement
from __future__ import annotations

import datetime
import logging
import time
from typing import TYPE_CHECKING, Any

from angrmanagement.logic import GlobalInfo

if TYPE_CHECKING:
    from collections.abc import Callable

    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext

m = ...


log = logging.getLogger(__name__)


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

    name: str
    progress_percentage: float
    last_text: str | None
    start_at: float
    blocking: bool
    _on_finish: Callable[[Instance, Any], None] | None

    def __init__(
        self, name: str, on_finish: Callable[[Instance, Any], None] | None = None, blocking: bool = False
    ) -> None:
        self.name = name
        self.progress_percentage = 0.0
        self.last_text = None
        self.start_at = 0.0
        self.blocking = blocking
        self.instance = None

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

    def run(self, inst):
        self.instance = inst
        log.info('Job "%s" started', self.name)
        self._progress_callback(0)
        self.start_at = time.time()
        r = self._run(inst)
        now = time.time()
        duration = now - self.start_at
        log.info('Job "%s" completed after %.2f seconds', self.name, duration)
        return r

    def _run(self, inst):
        raise NotImplementedError

    def finish(self, inst, result) -> None:  # pylint: disable=unused-argument
        inst.jobs = inst.jobs[1:]

        gui_thread_schedule_async(self._finish_progress)
        if self._on_finish:
            gui_thread_schedule_async(self._on_finish, (inst, result))

    def cancel(self) -> None:
        """Called from the GUI thread when the user presses Ctrl+C or presses a cancel button"""
        # lol. lmao even.
        if GlobalInfo.main_window.workspace.main_instance.current_job == self:
            tid = GlobalInfo.main_window.workspace.main_instance.worker_thread.ident
            res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(KeyboardInterrupt))
            if res != 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), 0)
                log.error("Failed to interrupt thread")

    def _progress_callback(self, percentage, text: str | None = None, inst=None) -> None:
        delta = percentage - self.progress_percentage

        if (delta > 0.02 or self.last_text != text) and time.time() - self.last_gui_updated_at >= 0.1:
            self.last_gui_updated_at = time.time()
            self.progress_percentage = percentage
            gui_thread_schedule_async(self._set_progress, args=(text,))

            # Dynamically update jobs view progress with instance
            if self.instance is not None and hasattr(self.instance, "callback_worker_progress_jobsView"):
                self.instance.callback_worker_progress_jobsView(self.instance.workspace, self.instance.current_job)

    def _set_progress(self, text: str | None = None) -> None:
        status = self.name
        if text:
            status += ": " + text
        GlobalInfo.main_window.progress(status, self.progress_percentage)

    def _finish_progress(self) -> None:
        pass

    def run(self, ctx: JobContext, inst: Instance):
        """Run the job. This method is called in a worker thread."""
        raise NotImplementedError

    def finish(self, inst: Instance, result: Any) -> None:
        """Runs after the job has finished in the GUI thread."""
        if self._on_finish is not None:
            self._on_finish(inst, result)
