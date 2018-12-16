
from .job import Job


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
