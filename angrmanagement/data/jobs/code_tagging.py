from __future__ import annotations

from typing import TYPE_CHECKING

from .job import Job

if TYPE_CHECKING:
    from angrmanagement.data.instance import Instance
    from angrmanagement.logic.jobmanager import JobContext


class CodeTaggingJob(Job):
    """
    Job for tagging functions.
    """

    def __init__(self, on_finish=None) -> None:
        super().__init__(name="Code tagging", on_finish=on_finish)

    def _run(self, ctx: JobContext, inst: Instance) -> None:
        func_count = len(inst.kb.functions)
        for i, func in enumerate(inst.kb.functions.values()):
            if func.alignment:
                continue
            ct = inst.project.analyses.CodeTagging(func)
            func.tags = tuple(ct.tags)

            percentage = i / func_count * 100
            ctx.set_progress(percentage)

    def __repr__(self) -> str:
        return "CodeTaggingJob"
