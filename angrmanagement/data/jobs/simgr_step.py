from __future__ import annotations

from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class SimgrStepJob(InstanceJob):
    """A job that runs the step method of the simulation manager."""

    def __init__(self, instance: Instance, simgr, until_branch: bool = False, step_callback=None) -> None:
        super().__init__("Simulation manager stepping", instance, on_finish=self._fire_completion_event)
        self._simgr = simgr
        self._until_branch = until_branch
        self._step_callback = step_callback

    def run(self, _: JobContext):
        if self._until_branch:
            orig_len = len(self._simgr.active)
            if orig_len > 0:
                while len(self._simgr.active) == orig_len:
                    self._simgr.step(step_func=self._step_callback)
                    self._simgr.prune()
        else:
            self._simgr.step(step_func=self._step_callback, num_inst=1)
            self._simgr.prune()

        return self._simgr

    def _fire_completion_event(self, result) -> None:
        self._simgr.am_event(src="job_done", job="step", result=result)

    def __repr__(self) -> str:
        if self._until_branch:
            return f"Stepping {self._simgr!r} until branch"
        else:
            return f"Stepping {self._simgr!r}"
