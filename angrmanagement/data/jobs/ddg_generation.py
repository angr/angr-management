from __future__ import annotations

from typing import TYPE_CHECKING, Any

import networkx

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class DDGGenerationJob(InstanceJob):
    """A job that runs the VSA_DDG analysis for a function at a given address."""

    def __init__(self, instance: Instance, addr: int) -> None:
        super().__init__("DDG generation", instance, on_finish=self._finish)
        self._addr = addr

    def run(self, _: JobContext):
        ddg = self.instance.project.analyses.VSA_DDG(vfg=self.instance.vfgs[self._addr], start_addr=self._addr)
        return ddg, networkx.relabel_nodes(ddg.graph, lambda n: n.insn_addr)

    def _finish(self, result: Any) -> None:
        self.instance.ddgs[self._addr] = result

    def __repr__(self) -> str:
        return f"Generating VSA_DDG for function at {self._addr:#x}"
