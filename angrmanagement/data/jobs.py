import networkx

from ..logic import GlobalInfo
from ..logic.threads import gui_thread_schedule_async


class Job:
    def __init__(self, name, on_finish=None):
        self.name = name
        self.progress_percentage = 0.

        # callbacks
        self._on_finish = on_finish

    def run(self, inst):
        raise NotImplementedError()

    def finish(self, inst, result):
        inst.jobs = inst.jobs[1:]

        gui_thread_schedule_async(self._finish_progress)
        if self._on_finish:
            gui_thread_schedule_async(self._on_finish)

    def _progress_callback(self, percentage):
        delta = percentage - self.progress_percentage

        if delta > 1.0:
            self.progress_percentage = percentage
            gui_thread_schedule_async(self._set_progress)

    def _set_progress(self):
        GlobalInfo.main_window.status = "Working... job %s" % self.name
        GlobalInfo.main_window.progress = self.progress_percentage

    def _finish_progress(self):
        GlobalInfo.main_window.progress_done()


class CFGGenerationJob(Job):

    DEFAULT_CFG_ARGS = {
        'normalize': True,  # this is what people naturally expect
        'resolve_indirect_jumps': True,
    }

    def __init__(self, on_finish=None, **kwargs):
        super(CFGGenerationJob, self).__init__(name='CFG generation', on_finish=on_finish)

        # TODO: sanitize arguments

        # make a copy
        cfg_args = dict(kwargs)
        for key, val in self.DEFAULT_CFG_ARGS.items():
            if key not in cfg_args:
                cfg_args[key] = val

        self.cfg_args = cfg_args

    def run(self, inst):
        cfg = inst.project.analyses.CFG(progress_callback=self._progress_callback,
                                        **self.cfg_args
                                        )
        cfb = inst.project.analyses.CFB(cfg=cfg)

        return cfg, cfb

    def finish(self, inst, result):
        cfg, cfb = result
        inst.cfb = cfb
        inst.cfg = cfg
        super(CFGGenerationJob, self).finish(inst, result)

    def __repr__(self):
        return "Generating CFG"


class CodeTaggingJob(Job):

    def __init__(self, on_finish=None):
        super(CodeTaggingJob, self).__init__(name="Code tagging", on_finish=on_finish)

    def run(self, inst):
        for func in inst.cfg.functions.values():
            ct = inst.project.analyses.CodeTagging(func)
            func.tags = tuple(ct.tags)

    def finish(self, inst, result):
        super(CodeTaggingJob, self).finish(inst, result)

    def __repr__(self):
        return "Tagging Code"


class SimgrStepJob(Job):
    def __init__(self, simgr, callback=None, until_branch=False):
        super(SimgrStepJob, self).__init__('Simulation manager stepping')
        self._simgr = simgr
        self._callback = callback
        self._until_branch = until_branch

    def run(self, inst):
        if self._until_branch:
            orig_len = len(self._simgr.active)
            if orig_len > 0:
                while len(self._simgr.active) == orig_len:
                    self._simgr.step()
                    self._simgr.prune()
        else:
            self._simgr.step()
            self._simgr.prune()

        return self._simgr

    def finish(self, inst, result):
        super(SimgrStepJob, self).finish(inst, result)
        if self._callback is not None:
            self._callback(result)

    def __repr__(self):
        if self._until_branch:
            return "Stepping %r until branch" % self._simgr
        else:
            return "Stepping %r" % self._simgr

    @classmethod
    def create(cls, simgr, **kwargs):
        def callback(result):
            simgr.am_event(src='job_done', job='step', result=result)
        return cls(simgr, callback=callback, **kwargs)


class SimgrExploreJob(Job):
    def __init__(self, simgr, find=None, avoid=None, step_callback=None, callback=None):
        super(SimgrExploreJob, self).__init__('Simulation manager exploring')
        self._simgr = simgr
        self._find = find
        self._avoid = avoid
        self._callback = callback
        self._step_callback = step_callback

    def run(self, inst):
        self._simgr.explore(find=self._find, avoid=self._avoid, step_func=self._step_callback)

        return self._simgr

    def finish(self, inst, result):
        super(SimgrExploreJob, self).finish(inst, result)
        self._callback(result)

    def __repr__(self):
        return "Exploring %r" % self._simgr

    @classmethod
    def create(cls, simgr, **kwargs):
        def callback(result):
            simgr.am_event(src='job_done', job='explore', result=result)
        return cls(simgr, callback=callback, **kwargs)


class VFGGenerationJob(Job):
    def __init__(self, addr):
        super(VFGGenerationJob, self).__init__('VFG generation')
        self._addr = addr

    def run(self, inst):
        return inst.project.analyses.VFG(function_start=self._addr)

    def finish(self, inst, result):
        super(VFGGenerationJob, self).finish(inst, result)
        inst.vfgs[self._addr] = result

    def __repr__(self):
        return "Generating VFG for function at %#x" % self._addr


class DDGGenerationJob(Job):
    def __init__(self, addr):
        super(DDGGenerationJob, self).__init__('DDG generation')
        self._addr = addr

    def run(self, inst):
        ddg = inst.project.analyses.VSA_DDG(vfg=inst.vfgs[self._addr], start_addr=self._addr)
        return (ddg, networkx.relabel_nodes(ddg.graph, lambda n: n.insn_addr))

    def finish(self, inst, result):
        super(DDGGenerationJob, self).finish(inst, result)
        inst.ddgs[self._addr] = result

    def __repr__(self):
        return "Generating VSA_DDG for function at %#x" % self._addr
