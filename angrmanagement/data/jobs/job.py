from typing import Optional
import logging
import time
import datetime

from ...logic import GlobalInfo
from ...logic.threads import gui_thread_schedule_async

try:
    from IPython.extensions.autoreload import ModuleReloader
    m = ModuleReloader()
    m.enabled = True
    m.check_all = True
    m.check()
except ImportError:
    m = None

l = logging.getLogger(__name__)

class Job:
    def __init__(self, name, on_finish=None, blocking=False):
        self.name = name
        self.progress_percentage = 0.
        self.last_text: Optional[str] = None
        self.start_at: float = 0.
        self.last_gui_updated_at: float = 0.
        self.blocking = blocking

        # callbacks
        self._on_finish = on_finish

        if m is not None and GlobalInfo.autoreload:
            prestate = dict(m.modules_mtimes)
            m.check()
            poststate = dict(m.modules_mtimes)
            if prestate != poststate:
                l.warning("Autoreload found changed modules")

    @property
    def time_elapsed(self) -> str:
        return str(datetime.timedelta(seconds=int(time.time() - self.start_at)))

    def run(self, inst):
        self.start_at = time.time()
        return self._run(inst)

    def _run(self, inst):
        raise NotImplementedError()

    def finish(self, inst, result): #pylint: disable=unused-argument
        inst.jobs = inst.jobs[1:]

        gui_thread_schedule_async(self._finish_progress)
        if self._on_finish:
            gui_thread_schedule_async(self._on_finish)

    def keyboard_interrupt(self):
        """Called from the GUI thread when the user presses Ctrl+C or presses a cancel button"""
        return

    def _progress_callback(self, percentage, text=None):
        delta = percentage - self.progress_percentage

        if (delta > 0.02 or self.last_text != text) and time.time() - self.last_gui_updated_at >= 0.1:
            self.last_gui_updated_at = time.time()
            self.progress_percentage = percentage
            gui_thread_schedule_async(self._set_progress, args=(text,))

    def _set_progress(self, text=None):
        if text:
            status = f"{self.name}: {text} - {self.time_elapsed}"
        else:
            status = f"{self.name} - {self.time_elapsed}"
        GlobalInfo.main_window.progress(status, self.progress_percentage)

    def _finish_progress(self):
        pass
