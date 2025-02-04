from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.deobfuscator import APIObfuscationFinder

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class APIDeobfuscationJob(InstanceJob):
    """
    Job for deobfuscating API usage.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("API Deobfuscation", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        self.instance.project.analyses[APIObfuscationFinder].prep(progress_callback=ctx.set_progress)(
            variable_kb=self.instance.pseudocode_variable_kb
        )

    def __repr__(self) -> str:
        return "APIDeobfuscationJob"
