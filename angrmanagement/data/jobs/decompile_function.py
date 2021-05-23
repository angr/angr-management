from .job import Job


class DecompileFunctionJob(Job):
    def __init__(self, function, on_finish=None, **kwargs):
        self.kwargs = kwargs
        self.function = function
        super().__init__(name="Decompiling", on_finish=on_finish)

    def run(self, inst):
        inst.project.analyses.Decompiler(
            self.function,
            flavor='pseudocode',
            **self.kwargs,
            progress_callback=self._progress_callback,
        )
        inst.project.analyses.ImportSourceCode(
            self.function,
            flavor='source',
            progress_callback=self._progress_callback,
        )
