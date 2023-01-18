import networkx

from .job import Job


class DDGGenerationJob(Job):
    def __init__(self, addr):
        super().__init__("DDG generation")
        self._addr = addr

    def _run(self, inst):
        ddg = inst.project.analyses.VSA_DDG(vfg=inst.vfgs[self._addr], start_addr=self._addr)
        return ddg, networkx.relabel_nodes(ddg.graph, lambda n: n.insn_addr)

    def finish(self, inst, result):
        super().finish(inst, result)
        inst.ddgs[self._addr] = result

    def __repr__(self):
        return "Generating VSA_DDG for function at %#x" % self._addr
