from __future__ import annotations

from angrmanagement.logic import GlobalInfo

from .job import Job


class DecompileFunctionJob(Job):
    """
    The job for running the decompiler analysis. You can trigger this by pressing f5 in a function.
    """

    def __init__(self, function, on_finish=None, blocking: bool = False, **kwargs) -> None:
        self.kwargs = kwargs
        self.function = function
        super().__init__(name="Decompiling", on_finish=on_finish, blocking=blocking)

    def _run(self, inst) -> None:
        decompiler = inst.project.analyses.Decompiler(
            self.function,
            flavor="pseudocode",
            variable_kb=inst.pseudocode_variable_kb,
            **self.kwargs,
            progress_callback=self._progress_callback,
        )
        # cache the result
        inst.kb.structured_code[(self.function.addr, "pseudocode")] = decompiler.cache

        GlobalInfo.main_window.workspace.plugins.decompile_callback(self.function)
