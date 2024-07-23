from __future__ import annotations

from typing import TYPE_CHECKING

from angrmanagement.logic import GlobalInfo

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class DecompileFunctionJob(InstanceJob):
    """
    The job for running the decompiler analysis. You can trigger this by pressing f5 in a function.
    """

    def __init__(self, instance: Instance, function, on_finish=None, blocking: bool = False, **kwargs) -> None:
        super().__init__("Decompiling", instance, on_finish=on_finish, blocking=blocking)
        self.kwargs = kwargs
        self.function = function

    def run(self, ctx: JobContext) -> None:
        decompiler = self.instance.project.analyses.Decompiler(
            self.function,
            flavor="pseudocode",
            variable_kb=self.instance.pseudocode_variable_kb,
            **self.kwargs,
            progress_callback=ctx.set_progress,
        )
        # cache the result
        self.instance.kb.structured_code[(self.function.addr, "pseudocode")] = decompiler.cache

        GlobalInfo.main_window.workspace.plugins.decompile_callback(self.function)
