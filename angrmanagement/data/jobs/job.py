
from ...logic import GlobalInfo
from ...logic.threads import gui_thread_schedule_async


class Job:
    def __init__(self, name, on_finish=None):
        self.name = name
        self.progress_percentage = 0.

        # callbacks
        self._on_finish = on_finish

    def run(self, inst):
        raise NotImplementedError()

    def finish(self, inst, result):
        inst.jobs = inst.jobs[1:]

        gui_thread_schedule_async(self._finish_progress)
        if self._on_finish:
            gui_thread_schedule_async(self._on_finish)

    def _progress_callback(self, percentage):
        delta = percentage - self.progress_percentage

        if delta > 1.0:
            self.progress_percentage = percentage
            gui_thread_schedule_async(self._set_progress)

    def _set_progress(self):
        GlobalInfo.main_window.status = "Working... job %s" % self.name
        GlobalInfo.main_window.progress = self.progress_percentage

    def _finish_progress(self):
        GlobalInfo.main_window.progress_done()

