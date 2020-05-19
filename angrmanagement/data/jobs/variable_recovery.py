from typing import TYPE_CHECKING
import time

from .job import Job

if TYPE_CHECKING:
    from ..instance import Instance


class VariableRecoveryJob(Job):
    """
    Identify variables and recover calling convention for every function.
    """

    def __init__(self, on_finish=None):
        super().__init__(name="Variable Recovery", on_finish=on_finish)

        self._last_progress_callback_triggered = None

    def run(self, inst: 'Instance'):
        inst.project.analyses.CompleteCallingConventions(
            recover_variables=True,
            low_priority=True,
            cfg=inst.cfg,
            progress_callback=self._progress_callback,
        )

    def _progress_callback(self, percentage, text=None, cfg=None):

        t = time.time()
        if self._last_progress_callback_triggered is not None and t - self._last_progress_callback_triggered < 0.2:
            return
        self._last_progress_callback_triggered = t

        text = "%.02f%%" % percentage

        super()._progress_callback(percentage, text=text)

    def finish(self, inst, result):
        super().finish(inst, result)

    def __repr__(self):
        return "<Variable Recovery Job>"
