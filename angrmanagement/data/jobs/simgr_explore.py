from .job import Job


class SimgrExploreJob(Job):
    def __init__(self, simgr, find=None, avoid=None, step_callback=None, until_callback=None, callback=None):
        super().__init__("Simulation manager exploring")
        self._simgr = simgr
        self._find = find
        self._avoid = avoid
        self._callback = callback
        self._step_callback = step_callback
        self._until_callback = until_callback
        self._interrupted = False

    def _run(self, inst):
        """Run the job. Runs in the worker thread."""

        def until_callback(*args, **kwargs):
            return self._interrupted or callable(self._until_callback) and self._until_callback(*args, **kwargs)

        self._simgr.explore(find=self._find, avoid=self._avoid, step_func=self._step_callback, until=until_callback)
        return self._simgr

    def finish(self, inst, result):
        super().finish(inst, result)
        self._callback(result)

    def __repr__(self):
        return "Exploring %r" % self._simgr

    def keyboard_interrupt(self):
        """Called from GUI thread. Worker thread will check self._interrupted periodically and exit the job early if
        needed."""
        self._interrupted = True

    @classmethod
    def create(cls, simgr, **kwargs):
        def callback(result):
            simgr.am_event(src="job_done", job="explore", result=result)

        return cls(simgr, callback=callback, **kwargs)
