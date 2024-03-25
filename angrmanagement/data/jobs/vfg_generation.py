from __future__ import annotations

from .job import Job


class VFGGenerationJob(Job):
    def __init__(self, addr: int) -> None:
        super().__init__("VFG generation")
        self._addr = addr

    def _run(self, inst):
        return inst.project.analyses.VFG(function_start=self._addr)

    def finish(self, inst, result) -> None:
        super().finish(inst, result)
        inst.vfgs[self._addr] = result

    def __repr__(self) -> str:
        return "Generating VFG for function at %#x" % self._addr
