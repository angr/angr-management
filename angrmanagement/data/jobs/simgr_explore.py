from __future__ import annotations

from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class SimgrExploreJob(InstanceJob):
    """A job that runs the explore method of a simulation manager."""

    def __init__(
        self, instance: Instance, simgr, find=None, avoid=None, step_callback=None, until_callback=None, on_finish=None
    ) -> None:
        super().__init__("Simulation manager exploring", instance, on_finish=on_finish)
        self._simgr = simgr
        self._find = find
        self._avoid = avoid
        self._step_callback = step_callback
        self._until_callback = until_callback
        self._interrupted = False

    def run(self, _: JobContext):
        """Run the job. Runs in the worker thread."""

        def until_callback(*args, **kwargs):
            return self._interrupted or callable(self._until_callback) and self._until_callback(*args, **kwargs)

        self._simgr.explore(find=self._find, avoid=self._avoid, step_func=self._step_callback, until=until_callback)
        return self._simgr

    def __repr__(self) -> str:
        return f"Exploring {self._simgr!r}"

    def cancel(self) -> None:
        """Called from GUI thread. Worker thread will check self._interrupted periodically and exit the job early if
        needed."""
        self._interrupted = True

    @classmethod
    def create(cls, instance: Instance, simgr, **kwargs):
        def callback(result) -> None:
            simgr.am_event(src="job_done", job="explore", result=result)

        return cls(instance, simgr, on_finish=callback, **kwargs)
