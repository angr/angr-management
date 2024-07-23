from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class VFGGenerationJob(Job):
    def __init__(self, addr: int) -> None:
        super().__init__("VFG generation", on_finish=self._finish)
        self._addr = addr

    def run(self, _: JobContext, inst: Instance):
        return inst.project.analyses.VFG(function_start=self._addr)

    def _finish(self, inst: Instance, result: Any) -> None:
        inst.vfgs[self._addr] = result

    def __repr__(self) -> str:
        return f"Generating VFG for function at {self._addr:#x}"
