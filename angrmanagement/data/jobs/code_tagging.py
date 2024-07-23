from __future__ import annotations

from typing import TYPE_CHECKING

from .job import InstanceJob

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class CodeTaggingJob(InstanceJob):
    """
    Job for tagging functions.
    """

    def __init__(self, instance: Instance, on_finish=None) -> None:
        super().__init__("Code tagging", instance, on_finish=on_finish)

    def run(self, ctx: JobContext) -> None:
        func_count = len(self.instance.kb.functions)
        for i, func in enumerate(self.instance.kb.functions.values()):
            if func.alignment:
                continue
            ct = self.instance.project.analyses.CodeTagging(func)
            func.tags = tuple(ct.tags)

            percentage = i / func_count * 100
            ctx.set_progress(percentage)

    def __repr__(self) -> str:
        return "CodeTaggingJob"
