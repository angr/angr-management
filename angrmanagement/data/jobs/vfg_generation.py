from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class VFGGenerationJob(InstanceJob):
    """A job that runs the VFG analysis for a function at a given address."""

    def __init__(self, instance: Instance, addr: int) -> None:
        super().__init__("VFG generation", instance, on_finish=self._finish)
        self._addr = addr

    def run(self, _: JobContext):
        return self.instance.project.analyses.VFG(function_start=self._addr)

    def _finish(self, result: Any) -> None:
        self.instance.vfgs[self._addr] = result

    def __repr__(self) -> str:
        return f"Generating VFG for function at {self._addr:#x}"
