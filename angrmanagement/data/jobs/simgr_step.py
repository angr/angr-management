from __future__ import annotations

from .job import Job


class SimgrStepJob(Job):
    def __init__(self, simgr, callback=None, until_branch: bool = False, step_callback=None) -> None:
        super().__init__("Simulation manager stepping")
        self._simgr = simgr
        self._callback = callback
        self._until_branch = until_branch
        self._step_callback = step_callback

    def _run(self, inst):
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

    def finish(self, inst, result) -> None:
        super().finish(inst, result)
        if self._callback is not None:
            self._callback(result)

    def __repr__(self) -> str:
        if self._until_branch:
            return f"Stepping {self._simgr!r} until branch"
        else:
            return f"Stepping {self._simgr!r}"

    @classmethod
    def create(cls, simgr, **kwargs):
        def callback(result) -> None:
            simgr.am_event(src="job_done", job="step", result=result)

        return cls(simgr, callback=callback, **kwargs)
