from .job import Job


class DecompileFunctionJob(Job):
    def __init__(self, function, on_finish=None, **kwargs):
        self.kwargs = kwargs
        self.function = function
        self.result = None
        super().__init__(name="Decompiling", on_finish=on_finish)

    def run(self, inst):
        d = inst.project.analyses.Decompiler(
            self.function,
            **self.kwargs,
            progress_callback=self._progress_callback,
        )
        self.result = d
        return d
