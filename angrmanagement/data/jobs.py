class Job(object):
    def run(self, inst):
        raise NotImplementedError()

    def finish(self, inst, result):
        inst.jobs = inst.jobs[1:]


class CFGGenerationJob(Job):
    def run(self, inst):
        return inst.proj.analyses.CFG()

    def finish(self, inst, result):
        super(CFGGenerationJob, self).finish(inst, result)
        inst.cfg = result

    def __repr__(self):
        return "Generating CFG"

def noop(_new_pg):
    pass


class PGStepJob(Job):
    def __init__(self, pg, callback=noop, until_branch=False):
        super(PGStepJob, self).__init__()
        self._pg = pg
        self._callback = callback
        self._until_branch = until_branch

    def run(self, inst):
        if self._until_branch:
            orig_len = len(self._pg.active)
            if orig_len > 0:
                while len(self._pg.active) == orig_len:
                    self._pg.step()
                    self._pg.prune()
        else:
            self._pg.step()
            self._pg.prune()

        return self._pg

    def finish(self, inst, result):
        super(PGStepJob, self).finish(inst, result)
        self._callback(result)

    def __repr__(self):
        if self.until_branch:
            return "Stepping %r until branch" % self._pg
        else:
            return "Stepping %r" % self._pg


class VFGGenerationJob(Job):
    def __init__(self, addr):
        super(VFGGenerationJob, self).__init__()
        self._addr = addr

    def run(self, inst):
        return inst.proj.analyses.VFG(cfg=inst.cfg, function_start=self._addr)

    def finish(self, inst, result):
        super(VFGGenerationJob, self).finish(inst, result)
        __import__('ipdb').set_trace()
        inst.vfgs[self._addr] = result

    def __repr__(self):
        return "Generating VFG for function at %#x" % self._addr
