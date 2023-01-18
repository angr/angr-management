from .job import Job


class VFGGenerationJob(Job):
    def __init__(self, addr):
        super().__init__("VFG generation")
        self._addr = addr

    def _run(self, inst):
        return inst.project.analyses.VFG(function_start=self._addr)

    def finish(self, inst, result):
        super().finish(inst, result)
        inst.vfgs[self._addr] = result

    def __repr__(self):
        return "Generating VFG for function at %#x" % self._addr
