from __future__ import annotations

from typing import TYPE_CHECKING, Any

import networkx

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class DDGGenerationJob(Job):
    """A job that runs the VSA_DDG analysis for a function at a given address."""

    def __init__(self, addr: int) -> None:
        super().__init__("DDG generation", on_finish=self._finish)
        self._addr = addr

    def run(self, _: JobContext, inst: Instance):
        ddg = inst.project.analyses.VSA_DDG(vfg=inst.vfgs[self._addr], start_addr=self._addr)
        return ddg, networkx.relabel_nodes(ddg.graph, lambda n: n.insn_addr)

    def _finish(self, inst: Instance, result: Any) -> None:
        inst.ddgs[self._addr] = result

    def __repr__(self) -> str:
        return f"Generating VSA_DDG for function at {self._addr:#x}"
